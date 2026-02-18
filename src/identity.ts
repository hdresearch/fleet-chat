import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { getDb } from "./store.js";
import { randomBytes } from "crypto";
import { execSync } from "child_process";

// Configure noble/ed25519 to use sha512
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

export interface IdentityInfo {
  publicKey: Buffer;
  privateKey: Buffer;
  agePublicKey: string;
  agePrivateKey: string;
  displayName: string;
  endpoint: string;
}

/**
 * Generate age keypair using age-keygen CLI.
 */
function generateAgeKeys(): { agePublicKey: string; agePrivateKey: string } {
  const output = execSync("age-keygen 2>&1", { encoding: "utf-8" });
  // Output format:
  // # created: ...
  // # public key: age1...
  // AGE-SECRET-KEY-1...
  let agePublicKey = "";
  let agePrivateKey = "";

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("# public key:")) {
      agePublicKey = trimmed.split("# public key:")[1].trim();
    } else if (trimmed.startsWith("AGE-SECRET-KEY-")) {
      agePrivateKey = trimmed;
    }
  }

  if (!agePublicKey || !agePrivateKey) {
    throw new Error("Failed to parse age-keygen output");
  }

  return { agePublicKey, agePrivateKey };
}

/**
 * Generate an Ed25519 keypair and age keys.
 */
export function generateIdentity(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  agePublicKey: string;
  agePrivateKey: string;
} {
  const seed = randomBytes(32);
  const publicKey = ed.getPublicKey(seed);
  const { agePublicKey, agePrivateKey } = generateAgeKeys();
  return { publicKey, privateKey: seed, agePublicKey, agePrivateKey };
}

/**
 * Initialize or retrieve identity from the database.
 */
export function getOrCreateIdentity(): IdentityInfo {
  const db = getDb();
  const endpoint = process.env.FLEET_CHAT_ENDPOINT || "http://localhost:3847";
  const displayName = process.env.FLEET_CHAT_DISPLAY_NAME || "unnamed-fleet";

  const row = db.prepare("SELECT * FROM identity WHERE id = 1").get() as any;

  if (row) {
    db.prepare("UPDATE identity SET endpoint = ?, display_name = ? WHERE id = 1")
      .run(endpoint, displayName);

    return {
      publicKey: Buffer.from(row.public_key),
      privateKey: Buffer.from(row.private_key),
      agePublicKey: row.age_public_key,
      agePrivateKey: row.age_private_key,
      displayName,
      endpoint,
    };
  }

  const { publicKey, privateKey, agePublicKey, agePrivateKey } = generateIdentity();

  db.prepare(
    `INSERT INTO identity (id, public_key, private_key, age_public_key, age_private_key, display_name, endpoint)
     VALUES (1, ?, ?, ?, ?, ?, ?)`
  ).run(Buffer.from(publicKey), Buffer.from(privateKey), agePublicKey, agePrivateKey, displayName, endpoint);

  console.log(`[fleet-chat] Generated identity: ${Buffer.from(publicKey).toString("base64")}`);
  console.log(`[fleet-chat] Age public key: ${agePublicKey}`);

  return {
    publicKey: Buffer.from(publicKey),
    privateKey: Buffer.from(privateKey),
    agePublicKey,
    agePrivateKey,
    displayName,
    endpoint,
  };
}

/**
 * Get identity (must already exist).
 */
export function getIdentity(): IdentityInfo | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM identity WHERE id = 1").get() as any;
  if (!row) return null;

  return {
    publicKey: Buffer.from(row.public_key),
    privateKey: Buffer.from(row.private_key),
    agePublicKey: row.age_public_key,
    agePrivateKey: row.age_private_key,
    displayName: row.display_name,
    endpoint: row.endpoint,
  };
}

export function getPublicKeyBase64(): string | null {
  const identity = getIdentity();
  return identity ? identity.publicKey.toString("base64") : null;
}
