import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { initTestDb, closeDb, getDb } from "../src/store.js";
import { getOrCreateIdentity } from "../src/identity.js";
import { receiveMessage, listMessages } from "../src/messages.js";
import { addContact } from "../src/contacts.js";
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

function createTestSender() {
  const seed = randomBytes(32);
  const publicKey = ed.getPublicKey(seed);

  const output = execSync("age-keygen 2>&1", { encoding: "utf-8" });
  let agePublicKey = "";
  let agePrivateKey = "";
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("# public key:")) agePublicKey = trimmed.split("# public key:")[1].trim();
    else if (trimmed.startsWith("AGE-SECRET-KEY-")) agePrivateKey = trimmed;
  }

  return {
    publicKey: Buffer.from(publicKey).toString("base64"),
    privateKey: seed,
    agePublicKey,
    agePrivateKey,
  };
}

describe("Messages", () => {
  let myIdentity: any;

  beforeEach(() => {
    initTestDb();
    process.env.FLEET_CHAT_ENDPOINT = "http://localhost:3847";
    process.env.FLEET_CHAT_DISPLAY_NAME = "test-fleet";
    myIdentity = getOrCreateIdentity();
  });

  afterEach(() => {
    closeDb();
  });

  describe("receiveMessage", () => {
    it("should accept message from trusted sender", () => {
      const sender = createTestSender();

      // Add sender as trusted contact
      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://sender:3847",
        displayName: "sender-fleet",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey,
      });

      // Build envelope
      const payload = JSON.stringify({
        type: "text",
        content: "Hello from sender!",
        metadata: {},
      });

      const encryptedPayload = ageEncrypt(payload, myIdentity.agePublicKey);
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();
      const signature = signEnvelope(sender.privateKey, encryptedPayload, nonce, timestamp);

      const envelope: MessageEnvelope = {
        id: ulid(),
        from: sender.publicKey,
        to: myIdentity.publicKey.toString("base64"),
        type: "text",
        payload: encryptedPayload,
        signature,
        timestamp,
        nonce,
      };

      const result = receiveMessage(envelope);
      expect(result.received).toBe(true);

      // Check message was stored
      const messages = listMessages({ with: sender.publicKey });
      expect(messages.count).toBe(1);
      expect(messages.messages[0].content).toBe("Hello from sender!");
      expect(messages.messages[0].direction).toBe("incoming");
    });

    it("should quarantine message from unknown sender", () => {
      const sender = createTestSender();

      const payload = JSON.stringify({ type: "text", content: "Who am I?", metadata: {} });
      const encryptedPayload = ageEncrypt(payload, myIdentity.agePublicKey);
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();
      const signature = signEnvelope(sender.privateKey, encryptedPayload, nonce, timestamp);

      const envelope: MessageEnvelope = {
        id: ulid(),
        from: sender.publicKey,
        to: myIdentity.publicKey.toString("base64"),
        type: "text",
        payload: encryptedPayload,
        signature,
        timestamp,
        nonce,
      };

      const result = receiveMessage(envelope);
      expect(result.received).toBe(true);

      // Message should NOT be in messages (it's quarantined)
      const messages = listMessages();
      expect(messages.count).toBe(0);

      // Check quarantine
      const db = getDb();
      const quarantined = db.prepare("SELECT * FROM quarantine WHERE status = 'pending'").all();
      expect(quarantined.length).toBe(1);
    });

    it("should silently drop message from blocked sender", () => {
      const sender = createTestSender();

      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://sender:3847",
        displayName: "blocked-fleet",
        trustLevel: "blocked",
        agePublicKey: sender.agePublicKey,
      });

      const payload = JSON.stringify({ type: "text", content: "Blocked!", metadata: {} });
      const encryptedPayload = ageEncrypt(payload, myIdentity.agePublicKey);
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();
      const signature = signEnvelope(sender.privateKey, encryptedPayload, nonce, timestamp);

      const envelope: MessageEnvelope = {
        id: ulid(),
        from: sender.publicKey,
        to: myIdentity.publicKey.toString("base64"),
        type: "text",
        payload: encryptedPayload,
        signature,
        timestamp,
        nonce,
      };

      const result = receiveMessage(envelope);
      expect(result.received).toBe(true); // Silently accepted

      // But no message stored
      const messages = listMessages();
      expect(messages.count).toBe(0);

      // And nothing quarantined
      const db = getDb();
      const quarantined = db.prepare("SELECT * FROM quarantine").all();
      expect(quarantined.length).toBe(0);
    });

    it("should reject message with wrong recipient", () => {
      const sender = createTestSender();
      const payload = JSON.stringify({ type: "text", content: "Wrong recipient", metadata: {} });
      const encryptedPayload = ageEncrypt(payload, myIdentity.agePublicKey);
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();
      const signature = signEnvelope(sender.privateKey, encryptedPayload, nonce, timestamp);

      const envelope: MessageEnvelope = {
        id: ulid(),
        from: sender.publicKey,
        to: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // wrong key
        type: "text",
        payload: encryptedPayload,
        signature,
        timestamp,
        nonce,
      };

      const result = receiveMessage(envelope);
      expect(result.received).toBe(false);
      expect(result.code).toBe("WRONG_RECIPIENT");
    });

    it("should reject invalid signature", () => {
      const sender = createTestSender();

      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://sender:3847",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey,
      });

      const payload = JSON.stringify({ type: "text", content: "Bad sig", metadata: {} });
      const encryptedPayload = ageEncrypt(payload, myIdentity.agePublicKey);
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();

      const envelope: MessageEnvelope = {
        id: ulid(),
        from: sender.publicKey,
        to: myIdentity.publicKey.toString("base64"),
        type: "text",
        payload: encryptedPayload,
        signature: Buffer.alloc(64).toString("base64"), // invalid sig
        timestamp,
        nonce,
      };

      const result = receiveMessage(envelope);
      expect(result.received).toBe(false);
      expect(result.code).toBe("INVALID_SIGNATURE");
    });

    it("should reject duplicate nonce (replay)", () => {
      const sender = createTestSender();

      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://sender:3847",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey,
      });

      const payload = JSON.stringify({ type: "text", content: "First", metadata: {} });
      const encryptedPayload = ageEncrypt(payload, myIdentity.agePublicKey);
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();
      const signature = signEnvelope(sender.privateKey, encryptedPayload, nonce, timestamp);

      const envelope: MessageEnvelope = {
        id: ulid(),
        from: sender.publicKey,
        to: myIdentity.publicKey.toString("base64"),
        type: "text",
        payload: encryptedPayload,
        signature,
        timestamp,
        nonce,
      };

      // First receive
      const r1 = receiveMessage(envelope);
      expect(r1.received).toBe(true);

      // Replay
      const r2 = receiveMessage({ ...envelope, id: ulid() });
      expect(r2.received).toBe(false);
      expect(r2.code).toBe("DUPLICATE_NONCE");
    });
  });
});
