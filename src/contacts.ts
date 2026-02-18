import { ulid } from "ulid";
import { getDb } from "./store.js";
import { TrustLevel, TrustLevelFromName, TrustLevelName, type Contact, type TrustLevelValue } from "./types.js";
import { randomBytes } from "crypto";

/**
 * Add a new contact.
 */
export function addContact(opts: {
  publicKey: string;
  endpoint: string;
  displayName?: string;
  trustLevel?: string | number;
  agePublicKey?: string;
  notes?: string;
}): Contact {
  const db = getDb();
  const id = ulid();

  let trustLevel: TrustLevelValue;
  if (typeof opts.trustLevel === "string") {
    trustLevel = TrustLevelFromName[opts.trustLevel] ?? TrustLevel.UNKNOWN;
  } else if (typeof opts.trustLevel === "number") {
    trustLevel = opts.trustLevel as TrustLevelValue;
  } else {
    trustLevel = TrustLevel.UNKNOWN;
  }

  db.prepare(
    `INSERT INTO contacts (id, public_key, display_name, endpoint, trust_level, age_public_key, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, opts.publicKey, opts.displayName || null, opts.endpoint, trustLevel, opts.agePublicKey || null, opts.notes || null);

  return getContactById(id)!;
}

/**
 * Get contact by ID.
 */
export function getContactById(id: string): Contact | null {
  const db = getDb();
  return db.prepare("SELECT * FROM contacts WHERE id = ?").get(id) as Contact | null;
}

/**
 * Get contact by public key (base64).
 */
export function getContactByPubkey(publicKey: string): Contact | null {
  const db = getDb();
  return db.prepare("SELECT * FROM contacts WHERE public_key = ?").get(publicKey) as Contact | null;
}

/**
 * List contacts with optional filters.
 */
export function listContacts(opts?: {
  trustLevel?: string;
  search?: string;
}): Contact[] {
  const db = getDb();
  let sql = "SELECT * FROM contacts WHERE 1=1";
  const params: any[] = [];

  if (opts?.trustLevel) {
    const level = TrustLevelFromName[opts.trustLevel];
    if (level !== undefined) {
      sql += " AND trust_level = ?";
      params.push(level);
    }
  }

  if (opts?.search) {
    sql += " AND display_name LIKE ?";
    params.push(`%${opts.search}%`);
  }

  sql += " ORDER BY added_at DESC";
  return db.prepare(sql).all(...params) as Contact[];
}

/**
 * Update a contact's trust level.
 */
export function setTrustLevel(publicKey: string, trustLevel: string): {
  oldLevel: string;
  newLevel: string;
  contact: Contact;
} | null {
  const contact = getContactByPubkey(publicKey);
  if (!contact) return null;

  const newLevel = TrustLevelFromName[trustLevel];
  if (newLevel === undefined) return null;

  const oldLevel = TrustLevelName[contact.trust_level];
  const db = getDb();
  db.prepare("UPDATE contacts SET trust_level = ? WHERE public_key = ?")
    .run(newLevel, publicKey);

  return {
    oldLevel,
    newLevel: trustLevel,
    contact: getContactByPubkey(publicKey)!,
  };
}

/**
 * Update last_seen for a contact.
 */
export function touchContact(publicKey: string): void {
  const db = getDb();
  db.prepare("UPDATE contacts SET last_seen = datetime('now') WHERE public_key = ?")
    .run(publicKey);
}

/**
 * Update contact endpoint.
 */
export function updateContactEndpoint(publicKey: string, newEndpoint: string): void {
  const db = getDb();
  db.prepare("UPDATE contacts SET endpoint = ? WHERE public_key = ?")
    .run(newEndpoint, publicKey);
}

/**
 * Delete a contact.
 */
export function deleteContact(publicKey: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM contacts WHERE public_key = ?").run(publicKey);
  return result.changes > 0;
}

/**
 * Generate a single-use friend-add link token.
 */
export function generateAddLinkToken(expiresInHours: number = 24): {
  token: string;
  expiresAt: string;
} {
  const db = getDb();
  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000).toISOString();

  db.prepare(
    `INSERT INTO add_link_tokens (token, expires_at) VALUES (?, ?)`
  ).run(token, expiresAt);

  return { token, expiresAt };
}

/**
 * Validate and consume an add-link token.
 */
export function consumeAddLinkToken(token: string, usedByKey?: string): boolean {
  const db = getDb();
  const row = db.prepare(
    "SELECT * FROM add_link_tokens WHERE token = ? AND used = 0 AND expires_at > datetime('now')"
  ).get(token) as any;

  if (!row) return false;

  db.prepare(
    "UPDATE add_link_tokens SET used = 1, used_by_key = ? WHERE token = ?"
  ).run(usedByKey || null, token);

  return true;
}

/**
 * Get trust level for a sender's public key.
 * Returns null if not in contacts.
 */
export function getTrustLevel(publicKey: string): TrustLevelValue | null {
  const contact = getContactByPubkey(publicKey);
  return contact ? contact.trust_level : null;
}
