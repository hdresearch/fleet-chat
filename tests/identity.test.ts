import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { initTestDb, closeDb } from "../src/store.js";
import { getOrCreateIdentity, getIdentity, getPublicKeyBase64 } from "../src/identity.js";

describe("Identity", () => {
  beforeEach(() => {
    initTestDb();
    process.env.FLEET_CHAT_ENDPOINT = "http://localhost:3847";
    process.env.FLEET_CHAT_DISPLAY_NAME = "test-fleet";
  });

  afterEach(() => {
    closeDb();
  });

  it("should generate a new identity on first call", () => {
    const identity = getOrCreateIdentity();

    expect(identity.publicKey).toBeInstanceOf(Buffer);
    expect(identity.publicKey.length).toBe(32);
    expect(identity.privateKey).toBeInstanceOf(Buffer);
    expect(identity.privateKey.length).toBe(32);
    expect(identity.agePublicKey).toMatch(/^age1/);
    expect(identity.agePrivateKey).toMatch(/^AGE-SECRET-KEY-/);
    expect(identity.displayName).toBe("test-fleet");
    expect(identity.endpoint).toBe("http://localhost:3847");
  });

  it("should return the same identity on subsequent calls", () => {
    const id1 = getOrCreateIdentity();
    const id2 = getOrCreateIdentity();

    expect(id1.publicKey.toString("base64")).toBe(id2.publicKey.toString("base64"));
    expect(id1.agePublicKey).toBe(id2.agePublicKey);
  });

  it("should get identity and public key base64", () => {
    getOrCreateIdentity();

    const identity = getIdentity();
    expect(identity).not.toBeNull();

    const pubKey = getPublicKeyBase64();
    expect(pubKey).not.toBeNull();
    expect(typeof pubKey).toBe("string");
    // Base64 of 32 bytes = 44 chars
    expect(pubKey!.length).toBe(44);
  });

  it("should return null if no identity exists", () => {
    const identity = getIdentity();
    expect(identity).toBeNull();
  });

  it("should update endpoint on subsequent calls", () => {
    getOrCreateIdentity();

    process.env.FLEET_CHAT_ENDPOINT = "http://new-host:3847";
    const identity = getOrCreateIdentity();

    expect(identity.endpoint).toBe("http://new-host:3847");
  });
});
