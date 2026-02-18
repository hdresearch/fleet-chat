import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { execSync } from "child_process";
import { randomBytes, createPrivateKey } from "crypto";
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
 * Convert an Ed25519 seed (32 bytes) to an SSH PEM private key.
 * This allows `age -d -i <pem-file>` to decrypt messages encrypted
 * to the corresponding SSH ed25519 public key.
 */
export function ed25519SeedToSshPem(seed: Buffer | Uint8Array): string {
  // PKCS8 DER prefix for Ed25519 private keys
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const derKey = Buffer.concat([pkcs8Prefix, Buffer.from(seed)]);

  const keyObj = createPrivateKey({
    key: derKey,
    format: "der",
    type: "pkcs8",
  });

  return keyObj.export({ type: "pkcs8", format: "pem" }) as string;
}

/**
 * Decrypt age-encrypted ciphertext.
 * Takes base64-encoded ciphertext and an age secret key.
 * Optionally accepts an ed25519 seed to also try SSH key decryption
 * (for messages encrypted via ageEncryptToSshKey).
 */
export function ageDecrypt(ciphertextBase64: string, ageSecretKey: string, ed25519Seed?: Buffer | Uint8Array): string {
  const tmpIn = join(tmpdir(), `fc-dec-${randomBytes(8).toString("hex")}.age`);
  const tmpKey = join(tmpdir(), `fc-key-${randomBytes(8).toString("hex")}`);
  const tmpSshKey = join(tmpdir(), `fc-ssh-${randomBytes(8).toString("hex")}.pem`);
  let hasSshKey = false;

  try {
    writeFileSync(tmpIn, Buffer.from(ciphertextBase64, "base64"));
    writeFileSync(tmpKey, ageSecretKey + "\n", { mode: 0o600 });

    let cmd = `age -d -i "${tmpKey}"`;

    // If ed25519 seed is provided, also write SSH PEM key for SSH-recipient decryption
    if (ed25519Seed && ed25519Seed.length === 32) {
      const pem = ed25519SeedToSshPem(ed25519Seed);
      writeFileSync(tmpSshKey, pem, { mode: 0o600 });
      hasSshKey = true;
      cmd += ` -i "${tmpSshKey}"`;
    }

    cmd += ` "${tmpIn}"`;

    const result = execSync(cmd, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    return result.toString("utf-8");
  } finally {
    try { unlinkSync(tmpIn); } catch {}
    try { unlinkSync(tmpKey); } catch {}
    if (hasSshKey) {
      try { unlinkSync(tmpSshKey); } catch {}
    }
  }
}

/**
 * Generate a random nonce (24 bytes) as base64.
 */
export function generateNonce(): string {
  return randomBytes(24).toString("base64");
}

/**
 * Convert an Ed25519 public key (base64) to SSH authorized_keys format.
 * This can be used with `age -R` to encrypt to an SSH ed25519 key.
 */
export function ed25519ToSshPubkey(pubkeyBase64: string): string {
  const keyBytes = Buffer.from(pubkeyBase64, "base64");
  if (keyBytes.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 key, got ${keyBytes.length}`);
  }

  // SSH wire format: string "ssh-ed25519" + 32-byte key
  const keyType = Buffer.from("ssh-ed25519");
  const typeLen = Buffer.alloc(4);
  typeLen.writeUInt32BE(keyType.length, 0);
  const keyLen = Buffer.alloc(4);
  keyLen.writeUInt32BE(keyBytes.length, 0);

  const wireFormat = Buffer.concat([typeLen, keyType, keyLen, keyBytes]);
  return `ssh-ed25519 ${wireFormat.toString("base64")}`;
}

/**
 * Encrypt to an SSH ed25519 public key using age -R.
 * Used when a contact has an ed25519 key but no explicit age public key.
 */
export function ageEncryptToSshKey(plaintext: string, sshPubkeyLine: string): string {
  const tmpIn = join(tmpdir(), `fc-enc-${randomBytes(8).toString("hex")}`);
  const tmpOut = tmpIn + ".age";
  const tmpRecipients = tmpIn + ".pub";

  try {
    writeFileSync(tmpIn, plaintext, "utf-8");
    writeFileSync(tmpRecipients, sshPubkeyLine + "\n", "utf-8");
    execSync(`age -R "${tmpRecipients}" -o "${tmpOut}" "${tmpIn}"`, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const ciphertext = readFileSync(tmpOut);
    return ciphertext.toString("base64");
  } finally {
    try { unlinkSync(tmpIn); } catch {}
    try { unlinkSync(tmpOut); } catch {}
    try { unlinkSync(tmpRecipients); } catch {}
  }
}
