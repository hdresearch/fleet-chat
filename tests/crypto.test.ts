import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { initTestDb, closeDb } from "../src/store.js";
import { getOrCreateIdentity } from "../src/identity.js";
import {
  sign,
  verify,
  signEnvelope,
  verifyEnvelope,
  buildSignInput,
  ageEncrypt,
  ageDecrypt,
  generateNonce,
} from "../src/crypto.js";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { randomBytes } from "crypto";

// Ensure sha512 is configured
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

describe("Crypto", () => {
  beforeEach(() => {
    initTestDb();
    process.env.FLEET_CHAT_ENDPOINT = "http://localhost:3847";
  });

  afterEach(() => {
    closeDb();
  });

  describe("Ed25519 sign/verify", () => {
    it("should sign and verify data", () => {
      const seed = randomBytes(32);
      const publicKey = ed.getPublicKey(seed);
      const data = Buffer.from("hello world");

      const sig = sign(seed, data);
      expect(sig).toBeInstanceOf(Uint8Array);
      expect(sig.length).toBe(64);

      const valid = verify(publicKey, data, sig);
      expect(valid).toBe(true);
    });

    it("should reject invalid signature", () => {
      const seed = randomBytes(32);
      const publicKey = ed.getPublicKey(seed);
      const data = Buffer.from("hello world");

      const sig = sign(seed, data);
      // Corrupt signature
      sig[0] ^= 0xff;

      const valid = verify(publicKey, data, sig);
      expect(valid).toBe(false);
    });

    it("should reject signature from wrong key", () => {
      const seed1 = randomBytes(32);
      const seed2 = randomBytes(32);
      const publicKey2 = ed.getPublicKey(seed2);
      const data = Buffer.from("hello world");

      const sig = sign(seed1, data);
      const valid = verify(publicKey2, data, sig);
      expect(valid).toBe(false);
    });
  });

  describe("Envelope signing", () => {
    it("should sign and verify envelope fields", () => {
      const identity = getOrCreateIdentity();
      const payload = Buffer.from("test payload").toString("base64");
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();

      const sig = signEnvelope(identity.privateKey, payload, nonce, timestamp);
      expect(typeof sig).toBe("string");

      const valid = verifyEnvelope(
        identity.publicKey.toString("base64"),
        payload,
        nonce,
        timestamp,
        sig
      );
      expect(valid).toBe(true);
    });

    it("should reject tampered payload", () => {
      const identity = getOrCreateIdentity();
      const payload = Buffer.from("test payload").toString("base64");
      const nonce = generateNonce();
      const timestamp = new Date().toISOString();

      const sig = signEnvelope(identity.privateKey, payload, nonce, timestamp);

      // Tamper with payload
      const tamperedPayload = Buffer.from("tampered").toString("base64");
      const valid = verifyEnvelope(
        identity.publicKey.toString("base64"),
        tamperedPayload,
        nonce,
        timestamp,
        sig
      );
      expect(valid).toBe(false);
    });
  });

  describe("Age encryption", () => {
    it("should encrypt and decrypt", () => {
      const identity = getOrCreateIdentity();
      const plaintext = "Hello, fleet-chat!";

      const encrypted = ageEncrypt(plaintext, identity.agePublicKey);
      expect(typeof encrypted).toBe("string");
      expect(encrypted.length).toBeGreaterThan(0);

      const decrypted = ageDecrypt(encrypted, identity.agePrivateKey);
      expect(decrypted).toBe(plaintext);
    });

    it("should encrypt JSON payloads", () => {
      const identity = getOrCreateIdentity();
      const payload = JSON.stringify({
        type: "text",
        content: "Hello from test!",
        metadata: { thread_id: "test123" },
      });

      const encrypted = ageEncrypt(payload, identity.agePublicKey);
      const decrypted = ageDecrypt(encrypted, identity.agePrivateKey);
      expect(JSON.parse(decrypted)).toEqual(JSON.parse(payload));
    });
  });

  describe("Nonce generation", () => {
    it("should generate unique 24-byte nonces", () => {
      const n1 = generateNonce();
      const n2 = generateNonce();

      expect(n1).not.toBe(n2);
      // 24 bytes base64 = 32 chars
      expect(Buffer.from(n1, "base64").length).toBe(24);
    });
  });
});
