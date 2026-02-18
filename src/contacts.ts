import { ulid } from "ulid";
import { getDb } from "./store.js";
import {
  TrustLevel,
  TrustLevelFromName,
  TrustLevelName,
  type Contact,
  type ContactKey,
  type Attestation,
  type TrustLevelValue,
} from "./types.js";
import { randomBytes } from "crypto";

// ─── Contact CRUD ───

/**
 * Add a new contact with a primary key.
 * Creates both a contacts row AND a contact_keys row.
 */
export function addContact(opts: {
  publicKey: string;
  endpoint: string;
  displayName?: string;
  trustLevel?: string | number;
  agePublicKey?: string;
  notes?: string;
  attestations?: string[];
}): Contact {
  const db = getDb();
  const contactId = ulid();

  let trustLevel: TrustLevelValue;
  if (typeof opts.trustLevel === "string") {
    trustLevel = TrustLevelFromName[opts.trustLevel] ?? TrustLevel.UNKNOWN;
  } else if (typeof opts.trustLevel === "number") {
    trustLevel = opts.trustLevel as TrustLevelValue;
  } else {
    trustLevel = TrustLevel.UNKNOWN;
  }

  // Insert contact row (public_key kept for backward compat)
  db.prepare(
    `INSERT INTO contacts (id, public_key, display_name, endpoint, trust_level, age_public_key, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    contactId,
    opts.publicKey,
    opts.displayName || null,
    opts.endpoint,
    trustLevel,
    opts.agePublicKey || null,
    opts.notes || null,
  );

  // Insert contact_keys row
  const keyId = ulid();
  db.prepare(
    `INSERT INTO contact_keys (id, contact_id, public_key, key_type, age_public_key)
     VALUES (?, ?, ?, 'ed25519', ?)`
  ).run(keyId, contactId, opts.publicKey, opts.agePublicKey || null);

  // Insert attestations if provided
  if (opts.attestations?.length) {
    const stmt = db.prepare(
      `INSERT INTO attestations (id, contact_id, url) VALUES (?, ?, ?)`
    );
    for (const url of opts.attestations) {
      stmt.run(ulid(), contactId, url);
    }
  }

  return getContactById(contactId)!;
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
 * Looks up through contact_keys first, falls back to contacts.public_key.
 */
export function getContactByPubkey(publicKey: string): Contact | null {
  const db = getDb();

  // Primary lookup: through contact_keys table
  const viaKey = db.prepare(`
    SELECT c.*, ck.public_key as ck_public_key, ck.age_public_key as ck_age_public_key
    FROM contact_keys ck
    JOIN contacts c ON c.id = ck.contact_id
    WHERE ck.public_key = ?
  `).get(publicKey) as any;

  if (viaKey) {
    // Return Contact with key info from contact_keys
    return {
      id: viaKey.id,
      public_key: viaKey.ck_public_key,
      display_name: viaKey.display_name,
      endpoint: viaKey.endpoint,
      trust_level: viaKey.trust_level,
      age_public_key: viaKey.ck_age_public_key || viaKey.age_public_key,
      added_at: viaKey.added_at,
      last_seen: viaKey.last_seen,
      notes: viaKey.notes,
    };
  }

  // Fallback: direct contacts.public_key lookup (pre-migration data)
  return db.prepare("SELECT * FROM contacts WHERE public_key = ?").get(publicKey) as Contact | null;
}

/**
 * Get contact ID for a public key. Used internally for efficient lookups.
 */
export function getContactIdByPubkey(publicKey: string): string | null {
  const db = getDb();
  const row = db.prepare(
    "SELECT contact_id FROM contact_keys WHERE public_key = ?"
  ).get(publicKey) as { contact_id: string } | undefined;
  if (row) return row.contact_id;

  // Fallback
  const contact = db.prepare(
    "SELECT id FROM contacts WHERE public_key = ?"
  ).get(publicKey) as { id: string } | undefined;
  return contact?.id ?? null;
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
  db.prepare("UPDATE contacts SET trust_level = ? WHERE id = ?")
    .run(newLevel, contact.id);

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
  const contactId = getContactIdByPubkey(publicKey);
  if (!contactId) return;
  db.prepare("UPDATE contacts SET last_seen = datetime('now') WHERE id = ?").run(contactId);
  db.prepare("UPDATE contact_keys SET last_used = datetime('now') WHERE contact_id = ? AND public_key = ?")
    .run(contactId, publicKey);
}

/**
 * Update contact endpoint.
 */
export function updateContactEndpoint(publicKey: string, newEndpoint: string): void {
  const db = getDb();
  const contactId = getContactIdByPubkey(publicKey);
  if (!contactId) return;
  db.prepare("UPDATE contacts SET endpoint = ? WHERE id = ?").run(newEndpoint, contactId);
}

/**
 * Delete a contact and its keys/attestations (CASCADE).
 */
export function deleteContact(publicKey: string): boolean {
  const db = getDb();
  const contactId = getContactIdByPubkey(publicKey);
  if (!contactId) {
    // Fallback: try direct delete
    const result = db.prepare("DELETE FROM contacts WHERE public_key = ?").run(publicKey);
    return result.changes > 0;
  }
  const result = db.prepare("DELETE FROM contacts WHERE id = ?").run(contactId);
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

/**
 * Update a contact's info if fields are missing or set to placeholder values.
 * Only updates fields that are currently null/empty/"unknown".
 * Returns true if any field was updated.
 */
export function updateContactInfo(publicKey: string, opts: {
  displayName?: string;
  endpoint?: string;
  agePublicKey?: string;
}): boolean {
  const db = getDb();
  const contact = getContactByPubkey(publicKey);
  if (!contact) return false;

  const updates: string[] = [];
  const params: any[] = [];

  if (opts.displayName && (!contact.display_name || contact.display_name === "")) {
    updates.push("display_name = ?");
    params.push(opts.displayName);
  }

  if (opts.endpoint && (!contact.endpoint || contact.endpoint === "unknown")) {
    updates.push("endpoint = ?");
    params.push(opts.endpoint);
  }

  if (opts.agePublicKey && !contact.age_public_key) {
    updates.push("age_public_key = ?");
    params.push(opts.agePublicKey);
    // Also update contact_keys
    db.prepare(
      "UPDATE contact_keys SET age_public_key = ? WHERE contact_id = ? AND public_key = ? AND age_public_key IS NULL"
    ).run(opts.agePublicKey, contact.id, publicKey);
  }

  if (updates.length === 0) return false;

  params.push(contact.id);
  db.prepare(`UPDATE contacts SET ${updates.join(", ")} WHERE id = ?`).run(...params);
  return true;
}

/**
 * Truncate a public key for human display.
 * "hAQe6hLEFTOG7E1sb/Cyut5prBqKEHn2/dbDgwIdcPc=" → "hAQe6h...dcPc"
 */
export function truncateKey(key: string): string {
  if (key.length <= 12) return key;
  const stripped = key.replace(/=+$/, "");
  return `${stripped.slice(0, 6)}...${stripped.slice(-4)}`;
}

/**
 * Get display name for a public key, falling back to truncated key.
 */
export function resolveDisplayName(publicKey: string): string {
  const contact = getContactByPubkey(publicKey);
  if (contact?.display_name) return contact.display_name;
  return truncateKey(publicKey);
}

// ─── Multi-key operations ───

/**
 * Add an additional key to an existing contact.
 */
export function addContactKey(contactId: string, opts: {
  publicKey: string;
  keyType?: string;
  agePublicKey?: string;
}): ContactKey {
  const db = getDb();
  const id = ulid();

  db.prepare(
    `INSERT INTO contact_keys (id, contact_id, public_key, key_type, age_public_key)
     VALUES (?, ?, ?, ?, ?)`
  ).run(id, contactId, opts.publicKey, opts.keyType || "ed25519", opts.agePublicKey || null);

  return db.prepare("SELECT * FROM contact_keys WHERE id = ?").get(id) as ContactKey;
}

/**
 * Get all keys for a contact.
 */
export function getContactKeys(contactId: string): ContactKey[] {
  const db = getDb();
  return db.prepare(
    "SELECT * FROM contact_keys WHERE contact_id = ? ORDER BY added_at DESC"
  ).all(contactId) as ContactKey[];
}

/**
 * Remove a key from a contact.
 */
export function removeContactKey(keyId: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM contact_keys WHERE id = ?").run(keyId);
  return result.changes > 0;
}

// ─── Attestation operations ───

/**
 * Add an attestation URL to a contact.
 */
export function addAttestation(contactId: string, url: string, opts?: {
  notes?: string;
}): Attestation {
  const db = getDb();
  const id = ulid();

  db.prepare(
    `INSERT INTO attestations (id, contact_id, url, notes) VALUES (?, ?, ?, ?)`
  ).run(id, contactId, url, opts?.notes || null);

  return db.prepare("SELECT * FROM attestations WHERE id = ?").get(id) as Attestation;
}

/**
 * Get all attestations for a contact.
 */
export function getAttestations(contactId: string): Attestation[] {
  const db = getDb();
  return db.prepare(
    "SELECT * FROM attestations WHERE contact_id = ? ORDER BY added_at DESC"
  ).all(contactId) as Attestation[];
}

/**
 * Update attestation verification status.
 */
export function verifyAttestation(attestationId: string, opts: {
  status: "verified" | "rejected";
  verifiedBy: string;
  notes?: string;
}): Attestation | null {
  const db = getDb();
  db.prepare(
    `UPDATE attestations SET status = ?, verified_at = datetime('now'), verified_by = ?, notes = COALESCE(?, notes) WHERE id = ?`
  ).run(opts.status, opts.verifiedBy, opts.notes || null, attestationId);

  return db.prepare("SELECT * FROM attestations WHERE id = ?").get(attestationId) as Attestation | null;
}

/**
 * Remove an attestation.
 */
export function removeAttestation(attestationId: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM attestations WHERE id = ?").run(attestationId);
  return result.changes > 0;
}

/**
 * Sync attestations from envelope — add any new URLs we haven't seen.
 */
export function syncAttestationsFromEnvelope(contactId: string, urls: string[]): number {
  const db = getDb();
  let added = 0;

  const existing = db.prepare(
    "SELECT url FROM attestations WHERE contact_id = ?"
  ).all(contactId) as { url: string }[];
  const existingUrls = new Set(existing.map((r) => r.url));

  for (const url of urls) {
    if (!existingUrls.has(url)) {
      const id = ulid();
      db.prepare(
        "INSERT INTO attestations (id, contact_id, url) VALUES (?, ?, ?)"
      ).run(id, contactId, url);
      added++;
    }
  }

  return added;
}
