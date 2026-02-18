import Database from "better-sqlite3";
import path from "path";

const SCHEMA = `
-- Identity (singleton)
CREATE TABLE IF NOT EXISTS identity (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  public_key BLOB NOT NULL,
  private_key BLOB NOT NULL,
  age_public_key TEXT NOT NULL,
  age_private_key TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT 'unnamed-fleet',
  endpoint TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_from BLOB
);

-- Contacts (public_key kept for backward compat but canonical lookup is via contact_keys)
CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  public_key TEXT UNIQUE,
  display_name TEXT,
  endpoint TEXT NOT NULL,
  trust_level INTEGER NOT NULL DEFAULT 0,
  age_public_key TEXT,
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT,
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_contacts_trust ON contacts(trust_level);
CREATE INDEX IF NOT EXISTS idx_contacts_pubkey ON contacts(public_key);

-- Contact keys: one contact can have many keys (multi-device, rotated keys)
CREATE TABLE IF NOT EXISTS contact_keys (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  public_key TEXT NOT NULL UNIQUE,
  key_type TEXT NOT NULL DEFAULT 'ed25519',
  age_public_key TEXT,
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used TEXT,
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contact_keys_pubkey ON contact_keys(public_key);
CREATE INDEX IF NOT EXISTS idx_contact_keys_contact ON contact_keys(contact_id);

-- Social attestations: URLs where a contact's public key can be verified
CREATE TABLE IF NOT EXISTS attestations (
  id TEXT PRIMARY KEY,
  contact_id TEXT NOT NULL,
  url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  verified_at TEXT,
  verified_by TEXT,
  notes TEXT,
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attestations_contact ON attestations(contact_id);
CREATE INDEX IF NOT EXISTS idx_attestations_status ON attestations(status);

-- Messages (decrypted, stored after send/receive)
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  from_key TEXT NOT NULL,
  to_key TEXT NOT NULL,
  type TEXT NOT NULL,
  content TEXT NOT NULL,
  metadata TEXT,
  direction TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'delivered',
  timestamp TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_key);
CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_key);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(type);

-- Outbound queue
CREATE TABLE IF NOT EXISTS outbound_queue (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  to_key TEXT NOT NULL,
  to_endpoint TEXT NOT NULL,
  envelope TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_retry_at TEXT NOT NULL,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_outbound_next_retry ON outbound_queue(next_retry_at);

-- Quarantine
CREATE TABLE IF NOT EXISTS quarantine (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  from_key TEXT NOT NULL,
  envelope TEXT NOT NULL,
  type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT,
  reviewed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
CREATE INDEX IF NOT EXISTS idx_quarantine_from ON quarantine(from_key);

-- Fleet Inbox
CREATE TABLE IF NOT EXISTS inbox (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  source_id TEXT,
  source_name TEXT,
  channel TEXT NOT NULL,
  content TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'text/plain',
  metadata TEXT,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  read INTEGER NOT NULL DEFAULT 0,
  archived INTEGER NOT NULL DEFAULT 0,
  original_message_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_inbox_channel ON inbox(channel);
CREATE INDEX IF NOT EXISTS idx_inbox_read ON inbox(read);
CREATE INDEX IF NOT EXISTS idx_inbox_archived ON inbox(archived);
CREATE INDEX IF NOT EXISTS idx_inbox_received ON inbox(received_at);

-- Nonce dedup
CREATE TABLE IF NOT EXISTS seen_nonces (
  nonce TEXT PRIMARY KEY,
  from_key TEXT NOT NULL,
  seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Friend-add tokens
CREATE TABLE IF NOT EXISTS add_link_tokens (
  token TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  used_by_key TEXT
);

-- Watcher state
CREATE TABLE IF NOT EXISTS watcher_state (
  name TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  last_poll TEXT,
  last_cursor TEXT,
  messages_ingested INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Key rotation history
CREATE TABLE IF NOT EXISTS key_history (
  id TEXT PRIMARY KEY,
  public_key BLOB NOT NULL,
  private_key BLOB NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT,
  rotated_at TEXT
);
`;

/**
 * Migrate existing contacts.public_key data into contact_keys table.
 * Idempotent — safe to run multiple times.
 */
function migrateContactKeys(db: Database.Database): void {
  // Find contacts that have a public_key but no corresponding contact_keys entry
  const rows = db.prepare(`
    SELECT c.id, c.public_key, c.age_public_key, c.added_at
    FROM contacts c
    WHERE c.public_key IS NOT NULL
      AND c.public_key != ''
      AND NOT EXISTS (
        SELECT 1 FROM contact_keys ck WHERE ck.contact_id = c.id AND ck.public_key = c.public_key
      )
  `).all() as { id: string; public_key: string; age_public_key: string | null; added_at: string }[];

  if (rows.length === 0) return;

  const insert = db.prepare(`
    INSERT OR IGNORE INTO contact_keys (id, contact_id, public_key, key_type, age_public_key, added_at)
    VALUES (?, ?, ?, 'ed25519', ?, ?)
  `);

  for (const row of rows) {
    // Generate a deterministic ID from contact_id + pubkey to ensure idempotency
    const keyId = `migrated-${row.id}`;
    insert.run(keyId, row.id, row.public_key, row.age_public_key, row.added_at);
  }

  if (rows.length > 0) {
    console.log(`[fleet-chat] Migrated ${rows.length} contact keys to contact_keys table`);
  }
}

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (!db) {
    const dbPath = process.env.FLEET_CHAT_DB_PATH || "./fleet-chat.db";
    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.exec(SCHEMA);
    migrateContactKeys(db);
  }
  return db;
}

export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}

// For testing — use in-memory DB
export function initTestDb(): Database.Database {
  db = new Database(":memory:");
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  // No migration needed for fresh test DBs
  return db;
}
