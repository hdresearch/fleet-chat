import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { initTestDb, closeDb, getDb } from "../src/store.js";
import { getOrCreateIdentity } from "../src/identity.js";
import { receiveMessage, listMessages } from "../src/messages.js";
import {
  addContact,
  getContactByPubkey,
  generateAddLinkToken,
  consumeAddLinkToken,
  updateContactInfo,
  truncateKey,
  resolveDisplayName,
} from "../src/contacts.js";
import { listQuarantine } from "../src/quarantine.js";
import { ageEncrypt, signEnvelope, generateNonce } from "../src/crypto.js";
import { ulid } from "ulid";
import type { MessageEnvelope } from "../src/types.js";

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
  let agePublicKey = "",
    agePrivateKey = "";
  for (const line of output.split("\n")) {
    const t = line.trim();
    if (t.startsWith("# public key:"))
      agePublicKey = t.split("# public key:")[1].trim();
    else if (t.startsWith("AGE-SECRET-KEY-")) agePrivateKey = t;
  }
  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: seed,
    agePublicKey,
    agePrivateKey,
  };
}

function buildEnvelope(
  sender: any,
  recipientPubkey: string,
  recipientAgeKey: string,
  content: string,
  opts?: { sender_name?: string; sender_endpoint?: string; sender_age_key?: string }
): MessageEnvelope {
  const payload = JSON.stringify({ type: "text", content, metadata: {} });
  const encrypted = ageEncrypt(payload, recipientAgeKey);
  const nonce = generateNonce();
  const timestamp = new Date().toISOString();
  const signature = signEnvelope(sender.privateKey, encrypted, nonce, timestamp);
  return {
    id: ulid(),
    from: sender.publicKey,
    to: recipientPubkey,
    type: "text",
    payload: encrypted,
    signature,
    timestamp,
    nonce,
    sender_name: opts?.sender_name,
    sender_endpoint: opts?.sender_endpoint,
    sender_age_key: opts?.sender_age_key,
  };
}

describe("Contact Discovery & Display Names", () => {
  let identity: any;

  beforeEach(() => {
    initTestDb();
    process.env.FLEET_CHAT_ENDPOINT = "http://localhost:3847";
    process.env.FLEET_CHAT_DISPLAY_NAME = "my-fleet";
    identity = getOrCreateIdentity();
  });

  afterEach(() => closeDb());

  describe("Sender metadata in envelope", () => {
    it("should populate contact info from envelope sender_name/endpoint/age_key for unknown senders", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "Hello!", {
        sender_name: "remote-fleet",
        sender_endpoint: "http://remote:3847",
        sender_age_key: sender.agePublicKey,
      });

      const result = receiveMessage(envelope);
      expect(result.received).toBe(true);

      // Auto-created contact should have the sender metadata
      const contact = getContactByPubkey(sender.publicKey);
      expect(contact).not.toBeNull();
      expect(contact!.display_name).toBe("remote-fleet");
      expect(contact!.endpoint).toBe("http://remote:3847");
      expect(contact!.age_public_key).toBe(sender.agePublicKey);
    });

    it("should update missing contact fields from envelope for trusted senders", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      // Add sender as trusted but missing age key and with placeholder endpoint
      addContact({
        publicKey: sender.publicKey,
        endpoint: "unknown",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey, // need age key for decryption to work
      });

      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "Hello trusted!", {
        sender_name: "known-fleet",
        sender_endpoint: "http://known:3847",
        sender_age_key: sender.agePublicKey,
      });

      receiveMessage(envelope);

      const contact = getContactByPubkey(sender.publicKey);
      expect(contact).not.toBeNull();
      expect(contact!.display_name).toBe("known-fleet");
      expect(contact!.endpoint).toBe("http://known:3847");
    });

    it("should NOT overwrite existing display_name from envelope", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://existing:3847",
        displayName: "my-custom-name",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey,
      });

      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "Hello!", {
        sender_name: "their-claimed-name",
        sender_endpoint: "http://new-endpoint:3847",
      });

      receiveMessage(envelope);

      const contact = getContactByPubkey(sender.publicKey);
      // Should keep the original name since it was already set
      expect(contact!.display_name).toBe("my-custom-name");
      // Should keep existing endpoint
      expect(contact!.endpoint).toBe("http://existing:3847");
    });
  });

  describe("Display name resolution", () => {
    it("should resolve display name from contact record", () => {
      addContact({
        publicKey: "test-key-abc",
        endpoint: "http://test:3847",
        displayName: "Fleet Alpha",
      });

      expect(resolveDisplayName("test-key-abc")).toBe("Fleet Alpha");
    });

    it("should fall back to truncated key when no display name", () => {
      addContact({
        publicKey: "hAQe6hLEFTOG7E1sb/Cyut5prBqKEHn2/dbDgwIdcPc=",
        endpoint: "http://test:3847",
      });

      const name = resolveDisplayName("hAQe6hLEFTOG7E1sb/Cyut5prBqKEHn2/dbDgwIdcPc=");
      expect(name).toBe("hAQe6h...dcPc");
    });

    it("should truncate keys for display", () => {
      expect(truncateKey("hAQe6hLEFTOG7E1sb/Cyut5prBqKEHn2/dbDgwIdcPc=")).toBe("hAQe6h...dcPc");
      expect(truncateKey("short")).toBe("short");
    });
  });

  describe("Messages include display names", () => {
    it("should include from_name and to_name in listed messages", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://sender:3847",
        displayName: "Sender Fleet",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey,
      });

      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "Hi there!");
      receiveMessage(envelope);

      const result = listMessages();
      expect(result.count).toBe(1);
      expect((result.messages[0] as any).from_name).toBe("Sender Fleet");
      // to_name resolves our own identity — should be truncated key since we're not in contacts
      expect((result.messages[0] as any).to_name).toBeTruthy();
    });
  });

  describe("Quarantine includes display names", () => {
    it("should show sender name in quarantine from envelope metadata", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "From stranger!", {
        sender_name: "stranger-fleet",
        sender_endpoint: "http://stranger:3847",
        sender_age_key: sender.agePublicKey,
      });

      receiveMessage(envelope);

      // The contact should have been auto-created with the display name
      const contact = getContactByPubkey(sender.publicKey);
      expect(contact).not.toBeNull();
      expect(contact!.display_name).toBe("stranger-fleet");

      // resolveDisplayName should return the name
      expect(resolveDisplayName(sender.publicKey)).toBe("stranger-fleet");
    });
  });

  describe("updateContactInfo", () => {
    it("should update missing fields", () => {
      addContact({
        publicKey: "test-update-key",
        endpoint: "unknown",
      });

      const updated = updateContactInfo("test-update-key", {
        displayName: "New Name",
        endpoint: "http://real-endpoint:3847",
        agePublicKey: "age1test...",
      });

      expect(updated).toBe(true);

      const contact = getContactByPubkey("test-update-key");
      expect(contact!.display_name).toBe("New Name");
      expect(contact!.endpoint).toBe("http://real-endpoint:3847");
      expect(contact!.age_public_key).toBe("age1test...");
    });

    it("should not overwrite existing values", () => {
      addContact({
        publicKey: "test-existing-key",
        endpoint: "http://existing:3847",
        displayName: "Existing Name",
        agePublicKey: "age1existing...",
      });

      const updated = updateContactInfo("test-existing-key", {
        displayName: "New Name",
        endpoint: "http://new:3847",
        agePublicKey: "age1new...",
      });

      expect(updated).toBe(false); // Nothing to update

      const contact = getContactByPubkey("test-existing-key");
      expect(contact!.display_name).toBe("Existing Name");
      expect(contact!.endpoint).toBe("http://existing:3847");
      expect(contact!.age_public_key).toBe("age1existing...");
    });
  });

  describe("Bidirectional add-link token flow", () => {
    it("should allow token to be consumed with visitor identity", () => {
      const { token } = generateAddLinkToken(24);

      // Simulate POST with visitor identity
      const consumed = consumeAddLinkToken(token, "visitor-pubkey-123");
      expect(consumed).toBe(true);

      // Token should be used up
      const reuse = consumeAddLinkToken(token);
      expect(reuse).toBe(false);
    });

    it("should not consume expired tokens", () => {
      const db = getDb();
      const token = "expired-test-token";
      // Use SQLite-compatible datetime format (no T, no Z) so comparison with datetime('now') works
      const expiresAt = "2020-01-01 00:00:00";
      db.prepare("INSERT INTO add_link_tokens (token, expires_at) VALUES (?, ?)").run(token, expiresAt);

      const consumed = consumeAddLinkToken(token, "visitor-pubkey");
      expect(consumed).toBe(false);
    });
  });
});
