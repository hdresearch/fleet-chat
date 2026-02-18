import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { execSync } from "child_process";
import { randomBytes } from "crypto";
import { tmpdir } from "os";
import { writeFileSync, readFileSync, unlinkSync } from "fs";
import { join } from "path";

// Ensure sha512 is configured
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

// ─── Ed25519 signing/verification ───

/**
 * Sign data with Ed25519 private key (seed).
 */
export function sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array {
  return ed.sign(data, privateKey);
}

/**
 * Verify an Ed25519 signature.
 */
export function verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed.verify(signature, data, publicKey);
  } catch {
    return false;
  }
}

/**
 * Construct the canonical sign input from message fields.
 * sign_input = payload_bytes || nonce_bytes || timestamp_utf8_bytes
 */
export function buildSignInput(payloadBase64: string, nonceBase64: string, timestamp: string): Uint8Array {
  const payloadBytes = Buffer.from(payloadBase64, "base64");
  const nonceBytes = Buffer.from(nonceBase64, "base64");
  const timestampBytes = Buffer.from(timestamp, "utf-8");
  return Buffer.concat([payloadBytes, nonceBytes, timestampBytes]);
}

/**
 * Sign a message envelope's fields.
 */
export function signEnvelope(
  privateKey: Uint8Array,
  payloadBase64: string,
  nonceBase64: string,
  timestamp: string
): string {
  const input = buildSignInput(payloadBase64, nonceBase64, timestamp);
  const sig = sign(privateKey, input);
  return Buffer.from(sig).toString("base64");
}

/**
 * Verify a message envelope's signature.
 */
export function verifyEnvelope(
  publicKeyBase64: string,
  payloadBase64: string,
  nonceBase64: string,
  timestamp: string,
  signatureBase64: string
): boolean {
  const pubKey = Buffer.from(publicKeyBase64, "base64");
  const sig = Buffer.from(signatureBase64, "base64");
  const input = buildSignInput(payloadBase64, nonceBase64, timestamp);
  return verify(pubKey, input, sig);
}

// ─── Age encryption/decryption (shelling out to age CLI) ───

/**
 * Encrypt plaintext to an age recipient (public key).
 * Returns base64-encoded ciphertext.
 */
export function ageEncrypt(plaintext: string, recipientAgeKey: string): string {
  const tmpIn = join(tmpdir(), `fc-enc-${randomBytes(8).toString("hex")}`);
  const tmpOut = tmpIn + ".age";

  try {
    writeFileSync(tmpIn, plaintext, "utf-8");
    execSync(`age -r "${recipientAgeKey}" -o "${tmpOut}" "${tmpIn}"`, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const ciphertext = readFileSync(tmpOut);
    return ciphertext.toString("base64");
  } finally {
    try { unlinkSync(tmpIn); } catch {}
    try { unlinkSync(tmpOut); } catch {}
  }
}

/**
 * Decrypt age-encrypted ciphertext.
 * Takes base64-encoded ciphertext and an age secret key.
 */
export function ageDecrypt(ciphertextBase64: string, ageSecretKey: string): string {
  const tmpIn = join(tmpdir(), `fc-dec-${randomBytes(8).toString("hex")}.age`);
  const tmpKey = join(tmpdir(), `fc-key-${randomBytes(8).toString("hex")}`);

  try {
    writeFileSync(tmpIn, Buffer.from(ciphertextBase64, "base64"));
    writeFileSync(tmpKey, ageSecretKey + "\n", { mode: 0o600 });
    const result = execSync(`age -d -i "${tmpKey}" "${tmpIn}"`, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    return result.toString("utf-8");
  } finally {
    try { unlinkSync(tmpIn); } catch {}
    try { unlinkSync(tmpKey); } catch {}
  }
}

/**
 * Generate a random nonce (24 bytes) as base64.
 */
export function generateNonce(): string {
  return randomBytes(24).toString("base64");
}
