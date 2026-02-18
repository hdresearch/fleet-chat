import { ulid } from "ulid";
import { getDb } from "./store.js";
import { getIdentity } from "./identity.js";
import { ageDecrypt } from "./crypto.js";
import { getContactByPubkey, setTrustLevel } from "./contacts.js";
import type { QuarantineItem, InboxItem, MessagePayload } from "./types.js";

/**
 * List quarantine items.
 */
export function listQuarantine(opts?: {
  status?: string;
  from?: string;
  limit?: number;
}): { items: QuarantineItem[]; count: number } {
  const db = getDb();
  let sql = "SELECT * FROM quarantine WHERE 1=1";
  const params: any[] = [];

  const status = opts?.status || "pending";
  sql += " AND status = ?";
  params.push(status);

  if (opts?.from) {
    sql += " AND from_key = ?";
    params.push(opts.from);
  }

  sql += " ORDER BY received_at DESC LIMIT ?";
  params.push(opts?.limit || 50);

  const items = db.prepare(sql).all(...params) as QuarantineItem[];
  return { items, count: items.length };
}

/**
 * Get a quarantine item by ID.
 */
export function getQuarantineItem(id: string): QuarantineItem | null {
  const db = getDb();
  return db.prepare("SELECT * FROM quarantine WHERE id = ?").get(id) as QuarantineItem | null;
}

/**
 * Approve a quarantined message: decrypt, store, push to inbox.
 */
export function approveQuarantine(id: string, opts?: {
  setTrust?: string;
  reviewedBy?: string;
}): { approved: boolean; messageId?: string; inboxId?: string; senderTrustUpdated?: boolean; error?: string } {
  const db = getDb();
  const item = getQuarantineItem(id);
  if (!item) return { approved: false, error: "Not found" };
  if (item.status !== "pending") return { approved: false, error: "Already reviewed" };

  const identity = getIdentity();
  if (!identity) return { approved: false, error: "Identity not initialized" };

  const envelope = JSON.parse(item.envelope);

  // Decrypt
  let payload: MessagePayload;
  try {
    const decrypted = ageDecrypt(envelope.payload, identity.agePrivateKey);
    payload = JSON.parse(decrypted);
  } catch (e: any) {
    return { approved: false, error: `Decryption failed: ${e.message}` };
  }

  // Store in messages
  db.prepare(
    `INSERT INTO messages (id, from_key, to_key, type, content, metadata, direction, status, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, 'incoming', 'delivered', ?)`
  ).run(envelope.id, item.from_key, envelope.to, envelope.type, payload.content, JSON.stringify(payload.metadata || {}), envelope.timestamp);

  // Push to inbox
  const contact = getContactByPubkey(item.from_key);
  const inboxId = addToInbox({
    source: "fleet-chat",
    sourceId: item.from_key,
    sourceName: contact?.display_name || item.from_key.slice(0, 12),
    channel: "direct",
    content: payload.content,
    metadata: payload.metadata,
    originalMessageId: envelope.id,
  });

  // Update quarantine status
  db.prepare(
    "UPDATE quarantine SET status = 'approved', reviewed_at = datetime('now'), reviewed_by = ? WHERE id = ?"
  ).run(opts?.reviewedBy || "api", id);

  // Optionally update trust level
  let senderTrustUpdated = false;
  if (opts?.setTrust) {
    const result = setTrustLevel(item.from_key, opts.setTrust);
    senderTrustUpdated = result !== null;
  }

  return { approved: true, messageId: envelope.id, inboxId, senderTrustUpdated };
}

/**
 * Reject a quarantined message.
 */
export function rejectQuarantine(id: string, opts?: {
  blockSender?: boolean;
  reviewedBy?: string;
}): { rejected: boolean; messageId?: string; senderBlocked?: boolean; error?: string } {
  const db = getDb();
  const item = getQuarantineItem(id);
  if (!item) return { rejected: false, error: "Not found" };
  if (item.status !== "pending") return { rejected: false, error: "Already reviewed" };

  db.prepare(
    "UPDATE quarantine SET status = 'rejected', reviewed_at = datetime('now'), reviewed_by = ? WHERE id = ?"
  ).run(opts?.reviewedBy || "api", id);

  let senderBlocked = false;
  if (opts?.blockSender) {
    const result = setTrustLevel(item.from_key, "blocked");
    senderBlocked = result !== null;
  }

  return { rejected: true, messageId: item.message_id, senderBlocked };
}

/**
 * Bulk approve all quarantined messages from a specific sender.
 */
export function bulkApproveFromSender(fromKey: string, opts?: {
  setTrust?: string;
}): { approved: number } {
  const db = getDb();
  const items = db.prepare(
    "SELECT id FROM quarantine WHERE from_key = ? AND status = 'pending'"
  ).all(fromKey) as { id: string }[];

  let approved = 0;
  for (const item of items) {
    const result = approveQuarantine(item.id, { setTrust: opts?.setTrust });
    if (result.approved) approved++;
  }

  return { approved };
}

/**
 * Purge expired quarantine items (30 days by default).
 */
export function purgeExpiredQuarantine(days: number = 30): number {
  const db = getDb();
  const result = db.prepare(
    `DELETE FROM quarantine WHERE status = 'pending' AND received_at < datetime('now', '-${days} days')`
  ).run();
  return result.changes;
}

// ─── Inbox helpers ───

/**
 * Add an item to the fleet inbox.
 */
export function addToInbox(opts: {
  source: string;
  sourceId?: string;
  sourceName?: string;
  channel: string;
  content: string;
  contentType?: string;
  metadata?: Record<string, unknown>;
  originalMessageId?: string;
}): string {
  const db = getDb();
  const id = ulid();

  db.prepare(
    `INSERT INTO inbox (id, source, source_id, source_name, channel, content, content_type, metadata, original_message_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    opts.source,
    opts.sourceId || null,
    opts.sourceName || null,
    opts.channel,
    opts.content,
    opts.contentType || "text/plain",
    opts.metadata ? JSON.stringify(opts.metadata) : null,
    opts.originalMessageId || null
  );

  return id;
}

/**
 * List inbox items.
 */
export function listInbox(opts?: {
  channel?: string;
  read?: boolean;
  archived?: boolean;
  since?: string;
  limit?: number;
}): { items: InboxItem[]; count: number; unread: number } {
  const db = getDb();
  let sql = "SELECT * FROM inbox WHERE 1=1";
  const params: any[] = [];

  if (opts?.channel) {
    sql += " AND channel = ?";
    params.push(opts.channel);
  }

  if (opts?.read !== undefined) {
    sql += " AND read = ?";
    params.push(opts.read ? 1 : 0);
  }

  const archived = opts?.archived ?? false;
  sql += " AND archived = ?";
  params.push(archived ? 1 : 0);

  if (opts?.since) {
    sql += " AND received_at > ?";
    params.push(opts.since);
  }

  sql += " ORDER BY received_at DESC LIMIT ?";
  params.push(opts?.limit || 50);

  const items = db.prepare(sql).all(...params) as InboxItem[];
  const unread = (db.prepare("SELECT COUNT(*) as c FROM inbox WHERE read = 0 AND archived = 0").get() as any).c;

  return { items, count: items.length, unread };
}

/**
 * Get inbox item by ID.
 */
export function getInboxItem(id: string): InboxItem | null {
  const db = getDb();
  return db.prepare("SELECT * FROM inbox WHERE id = ?").get(id) as InboxItem | null;
}

/**
 * Mark inbox item as read.
 */
export function markInboxRead(id: string): boolean {
  const db = getDb();
  const result = db.prepare("UPDATE inbox SET read = 1 WHERE id = ?").run(id);
  return result.changes > 0;
}

/**
 * Archive inbox item.
 */
export function archiveInboxItem(id: string): boolean {
  const db = getDb();
  const result = db.prepare("UPDATE inbox SET archived = 1 WHERE id = ?").run(id);
  return result.changes > 0;
}

/**
 * Get unread count by channel.
 */
export function getUnreadCount(): { unread: number; by_channel: Record<string, number> } {
  const db = getDb();
  const total = (db.prepare("SELECT COUNT(*) as c FROM inbox WHERE read = 0 AND archived = 0").get() as any).c;
  const rows = db.prepare(
    "SELECT channel, COUNT(*) as c FROM inbox WHERE read = 0 AND archived = 0 GROUP BY channel"
  ).all() as { channel: string; c: number }[];

  const byChannel: Record<string, number> = {};
  for (const row of rows) byChannel[row.channel] = row.c;

  return { unread: total, by_channel: byChannel };
}
