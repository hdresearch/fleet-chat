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

-- Contacts
CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL UNIQUE,
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

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (!db) {
    const dbPath = process.env.FLEET_CHAT_DB_PATH || "./fleet-chat.db";
    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    db.exec(SCHEMA);
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
  return db;
}
