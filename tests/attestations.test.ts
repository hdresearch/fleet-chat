import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { initTestDb, closeDb, getDb } from "../src/store.js";
import { getOrCreateIdentity } from "../src/identity.js";
import { receiveMessage, listMessages } from "../src/messages.js";
import {
  addContact,
  getContactByPubkey,
  getContactKeys,
  addContactKey,
  removeContactKey,
  getAttestations,
  addAttestation,
  verifyAttestation,
  removeAttestation,
  syncAttestationsFromEnvelope,
  getContactIdByPubkey,
} from "../src/contacts.js";
import { ageEncrypt, signEnvelope, generateNonce, ed25519ToSshPubkey } from "../src/crypto.js";
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
  opts?: {
    sender_name?: string;
    sender_endpoint?: string;
    sender_age_key?: string;
    attestations?: string[];
  }
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
    attestations: opts?.attestations,
  };
}

describe("Social Attestations & Multi-Key", () => {
  let identity: any;

  beforeEach(() => {
    initTestDb();
    process.env.FLEET_CHAT_ENDPOINT = "http://localhost:3847";
    process.env.FLEET_CHAT_DISPLAY_NAME = "my-fleet";
    identity = getOrCreateIdentity();
  });

  afterEach(() => closeDb());

  describe("Contact keys table", () => {
    it("should create contact_keys entry when adding contact", () => {
      const contact = addContact({
        publicKey: "test-key-1",
        endpoint: "http://fleet1:3847",
        displayName: "Fleet One",
        trustLevel: "trusted",
        agePublicKey: "age1test...",
      });

      const keys = getContactKeys(contact.id);
      expect(keys.length).toBe(1);
      expect(keys[0].public_key).toBe("test-key-1");
      expect(keys[0].key_type).toBe("ed25519");
      expect(keys[0].age_public_key).toBe("age1test...");
    });

    it("should look up contact through contact_keys", () => {
      addContact({
        publicKey: "lookup-key",
        endpoint: "http://fleet:3847",
        displayName: "Lookup Fleet",
      });

      const contact = getContactByPubkey("lookup-key");
      expect(contact).not.toBeNull();
      expect(contact!.display_name).toBe("Lookup Fleet");
      expect(contact!.public_key).toBe("lookup-key");
    });

    it("should support multiple keys per contact", () => {
      const contact = addContact({
        publicKey: "primary-key",
        endpoint: "http://fleet:3847",
        displayName: "Multi-Key Fleet",
      });

      addContactKey(contact.id, {
        publicKey: "secondary-key",
        keyType: "ed25519",
        agePublicKey: "age1secondary...",
      });

      const keys = getContactKeys(contact.id);
      expect(keys.length).toBe(2);

      // Both keys should resolve to the same contact
      const c1 = getContactByPubkey("primary-key");
      const c2 = getContactByPubkey("secondary-key");
      expect(c1!.id).toBe(c2!.id);
      expect(c1!.display_name).toBe("Multi-Key Fleet");
    });

    it("should remove keys", () => {
      const contact = addContact({
        publicKey: "key-to-keep",
        endpoint: "http://fleet:3847",
      });

      const newKey = addContactKey(contact.id, {
        publicKey: "key-to-remove",
      });

      expect(getContactKeys(contact.id).length).toBe(2);

      removeContactKey(newKey.id);
      expect(getContactKeys(contact.id).length).toBe(1);
      expect(getContactByPubkey("key-to-remove")).toBeFalsy();
    });

    it("should get contact ID by pubkey", () => {
      const contact = addContact({
        publicKey: "id-lookup-key",
        endpoint: "http://fleet:3847",
      });

      const id = getContactIdByPubkey("id-lookup-key");
      expect(id).toBe(contact.id);

      expect(getContactIdByPubkey("nonexistent")).toBeNull();
    });
  });

  describe("Attestation CRUD", () => {
    it("should add attestations to a contact", () => {
      const contact = addContact({
        publicKey: "attest-key",
        endpoint: "http://fleet:3847",
        attestations: ["https://github.com/testuser.keys", "https://keyoxide.org/test"],
      });

      const attestations = getAttestations(contact.id);
      expect(attestations.length).toBe(2);
      expect(attestations.map((a) => a.url)).toContain("https://github.com/testuser.keys");
      expect(attestations.map((a) => a.url)).toContain("https://keyoxide.org/test");
      expect(attestations[0].status).toBe("pending");
    });

    it("should verify/reject attestations", () => {
      const contact = addContact({
        publicKey: "verify-key",
        endpoint: "http://fleet:3847",
      });

      const attestation = addAttestation(contact.id, "https://github.com/user.keys");
      expect(attestation.status).toBe("pending");

      const verified = verifyAttestation(attestation.id, {
        status: "verified",
        verifiedBy: "operator",
        notes: "Confirmed key matches",
      });

      expect(verified!.status).toBe("verified");
      expect(verified!.verified_by).toBe("operator");
      expect(verified!.verified_at).not.toBeNull();
    });

    it("should remove attestations", () => {
      const contact = addContact({
        publicKey: "remove-attest-key",
        endpoint: "http://fleet:3847",
      });

      const attestation = addAttestation(contact.id, "https://example.com/keys");
      expect(getAttestations(contact.id).length).toBe(1);

      removeAttestation(attestation.id);
      expect(getAttestations(contact.id).length).toBe(0);
    });

    it("should sync attestations from envelope without duplicates", () => {
      const contact = addContact({
        publicKey: "sync-key",
        endpoint: "http://fleet:3847",
      });

      addAttestation(contact.id, "https://github.com/user.keys");

      // Sync with overlapping + new URLs
      const added = syncAttestationsFromEnvelope(contact.id, [
        "https://github.com/user.keys", // existing — should not duplicate
        "https://twitter.com/user/status/123", // new
      ]);

      expect(added).toBe(1); // Only the new one
      expect(getAttestations(contact.id).length).toBe(2);
    });
  });

  describe("Attestations from message envelope", () => {
    it("should store attestation URLs from incoming message envelope", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      const envelope = buildEnvelope(sender, myPubkey, identity.agePublicKey, "Hello with attestations!", {
        sender_name: "attested-fleet",
        sender_endpoint: "http://attested:3847",
        sender_age_key: sender.agePublicKey,
        attestations: [
          "https://github.com/attested-user.keys",
          "https://keyoxide.org/hkp/user@example.com",
        ],
      });

      receiveMessage(envelope);

      const contact = getContactByPubkey(sender.publicKey);
      expect(contact).not.toBeNull();

      const attestations = getAttestations(contact!.id);
      expect(attestations.length).toBe(2);
      expect(attestations.map((a) => a.url)).toContain("https://github.com/attested-user.keys");
      expect(attestations[0].status).toBe("pending"); // Not auto-verified
    });

    it("should accumulate attestations across multiple messages", () => {
      const sender = createSender();
      const myPubkey = identity.publicKey.toString("base64");

      // Add sender as trusted so messages get processed (not quarantined)
      addContact({
        publicKey: sender.publicKey,
        endpoint: "http://sender:3847",
        displayName: "Trusted Sender",
        trustLevel: "trusted",
        agePublicKey: sender.agePublicKey,
      });

      // First message with one attestation
      receiveMessage(
        buildEnvelope(sender, myPubkey, identity.agePublicKey, "Message 1", {
          attestations: ["https://github.com/user.keys"],
        })
      );

      // Second message with overlapping + new attestation
      receiveMessage(
        buildEnvelope(sender, myPubkey, identity.agePublicKey, "Message 2", {
          attestations: ["https://github.com/user.keys", "https://twitter.com/user/123"],
        })
      );

      const contact = getContactByPubkey(sender.publicKey);
      const attestations = getAttestations(contact!.id);
      expect(attestations.length).toBe(2); // No duplicates
    });
  });

  describe("SSH key formatting", () => {
    it("should convert ed25519 public key to SSH format", () => {
      const sshKey = ed25519ToSshPubkey(identity.publicKey.toString("base64"));
      expect(sshKey).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5/);

      // Should decode back to proper structure
      const parts = sshKey.split(" ");
      expect(parts[0]).toBe("ssh-ed25519");
      const wireBytes = Buffer.from(parts[1], "base64");
      // 4 bytes type length + 11 bytes "ssh-ed25519" + 4 bytes key length + 32 bytes key = 51
      expect(wireBytes.length).toBe(51);
    });

    it("should reject non-32-byte keys", () => {
      expect(() => ed25519ToSshPubkey(Buffer.from("short").toString("base64"))).toThrow();
    });
  });

  describe("Cascade delete", () => {
    it("should delete keys and attestations when contact is deleted", async () => {
      const contact = addContact({
        publicKey: "delete-cascade-key",
        endpoint: "http://fleet:3847",
        attestations: ["https://example.com/keys"],
      });

      addContactKey(contact.id, { publicKey: "extra-key" });

      expect(getContactKeys(contact.id).length).toBe(2);
      expect(getAttestations(contact.id).length).toBe(1);

      const { deleteContact } = await import("../src/contacts.js");
      deleteContact("delete-cascade-key");

      // Keys and attestations should be gone
      expect(getContactKeys(contact.id).length).toBe(0);
      expect(getAttestations(contact.id).length).toBe(0);
    });
  });
});
