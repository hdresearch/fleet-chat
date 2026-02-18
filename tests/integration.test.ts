import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { initTestDb, closeDb, getDb } from "../src/store.js";
import { getOrCreateIdentity } from "../src/identity.js";
import { receiveMessage } from "../src/messages.js";
import { addContact, listContacts, setTrustLevel, getContactByPubkey, generateAddLinkToken, consumeAddLinkToken } from "../src/contacts.js";
import { listQuarantine, approveQuarantine, rejectQuarantine, listInbox, getUnreadCount, markInboxRead } from "../src/quarantine.js";
import { ageEncrypt, signEnvelope, generateNonce } from "../src/crypto.js";
import { ulid } from "ulid";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { randomBytes } from "crypto";
import { execSync } from "child_process";

ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

function createSender() {
  const seed = randomBytes(32);
  const publicKey = ed.getPublicKey(seed);
  const output = execSync("age-keygen 2>&1", { encoding: "utf-8" });
  let agePublicKey = "", agePrivateKey = "";
  for (const line of output.split("\n")) {
    const t = line.trim();
    if (t.startsWith("# public key:")) agePublicKey = t.split("# public key:")[1].trim();
    else if (t.startsWith("AGE-SECRET-KEY-")) agePrivateKey = t;
  }
  return { publicKey: Buffer.from(publicKey).toString("base64"), privateKey: seed, agePublicKey, agePrivateKey };
}

function buildEnvelope(sender: any, recipientPubkey: string, recipientAgeKey: string, content: string) {
  const payload = JSON.stringify({ type: "text", content, metadata: {} });
  const encrypted = ageEncrypt(payload, recipientAgeKey);
  const nonce = generateNonce();
  const timestamp = new Date().toISOString();
  const signature = signEnvelope(sender.privateKey, encrypted, nonce, timestamp);
  return { id: ulid(), from: sender.publicKey, to: recipientPubkey, type: "text" as const, payload: encrypted, signature, timestamp, nonce };
}

describe("Integration", () => {
  let identity: any;

  beforeEach(() => {
    initTestDb();
    process.env.FLEET_CHAT_ENDPOINT = "http://localhost:3847";
    identity = getOrCreateIdentity();
  });

  afterEach(() => closeDb());

  describe("Quarantine flow", () => {
    it("should quarantine → approve → inbox", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      // Send from unknown sender
      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "Hello stranger!");
      const result = receiveMessage(envelope);
      expect(result.received).toBe(true);

      // Should be in quarantine
      const q = listQuarantine();
      expect(q.count).toBe(1);
      expect(q.items[0].from_key).toBe(sender.publicKey);

      // Approve it
      const approveResult = approveQuarantine(q.items[0].id, { setTrust: "trusted" });
      expect(approveResult.approved).toBe(true);
      expect(approveResult.senderTrustUpdated).toBe(true);

      // Should be in inbox now
      const inbox = listInbox();
      expect(inbox.count).toBe(1);
      expect(inbox.items[0].content).toBe("Hello stranger!");

      // Sender should be trusted now
      const contact = getContactByPubkey(sender.publicKey);
      expect(contact).not.toBeNull();
      expect(contact!.trust_level).toBe(2); // trusted
    });

    it("should quarantine → reject with block", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "Spam message");
      receiveMessage(envelope);

      const q = listQuarantine();
      const rejectResult = rejectQuarantine(q.items[0].id, { blockSender: true });
      expect(rejectResult.rejected).toBe(true);
      expect(rejectResult.senderBlocked).toBe(true);

      // Sender should be blocked
      const contact = getContactByPubkey(sender.publicKey);
      expect(contact!.trust_level).toBe(3); // blocked

      // Further messages should be silently dropped
      const envelope2 = buildEnvelope(sender, myPubkey, identity.agePublicKey, "More spam");
      const r2 = receiveMessage(envelope2);
      expect(r2.received).toBe(true); // silently accepted
    });
  });

  describe("Contact management", () => {
    it("should add and list contacts", () => {
      addContact({
        publicKey: "test-key-1",
        endpoint: "http://fleet1:3847",
        displayName: "Fleet One",
        trustLevel: "trusted",
      });

      addContact({
        publicKey: "test-key-2",
        endpoint: "http://fleet2:3847",
        displayName: "Fleet Two",
        trustLevel: "pending",
      });

      const all = listContacts();
      expect(all.length).toBe(2);

      const trusted = listContacts({ trustLevel: "trusted" });
      expect(trusted.length).toBe(1);
      expect(trusted[0].display_name).toBe("Fleet One");
    });

    it("should change trust level", () => {
      addContact({
        publicKey: "test-key",
        endpoint: "http://fleet:3847",
        trustLevel: "unknown",
      });

      const result = setTrustLevel("test-key", "trusted");
      expect(result).not.toBeNull();
      expect(result!.oldLevel).toBe("unknown");
      expect(result!.newLevel).toBe("trusted");
    });
  });

  describe("Add-link tokens", () => {
    it("should generate and consume tokens", () => {
      const { token, expiresAt } = generateAddLinkToken(24);
      expect(token.length).toBe(64); // 32 bytes hex
      expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());

      const valid = consumeAddLinkToken(token);
      expect(valid).toBe(true);

      // Should not be reusable
      const reuse = consumeAddLinkToken(token);
      expect(reuse).toBe(false);
    });
  });

  describe("Inbox operations", () => {
    it("should track unread counts", () => {
      const sender = createSender();
      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://sender:3847",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey,
      });

      const myPubkey = identity.publicKey.toString("base64");

      // Send two messages
      receiveMessage(buildEnvelope(sender, myPubkey, identity.agePublicKey, "Message 1"));
      receiveMessage(buildEnvelope(sender, myPubkey, identity.agePublicKey, "Message 2"));

      const unread = getUnreadCount();
      expect(unread.unread).toBe(2);
      expect(unread.by_channel.direct).toBe(2);

      // Mark one as read
      const inbox = listInbox();
      markInboxRead(inbox.items[0].id);

      const unread2 = getUnreadCount();
      expect(unread2.unread).toBe(1);
    });
  });
});
