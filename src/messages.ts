import { ulid } from "ulid";
import { getDb } from "./store.js";
import { getIdentity, type IdentityInfo } from "./identity.js";
import { ageEncrypt, ageEncryptToSshKey, ed25519ToSshPubkey, ageDecrypt, signEnvelope, verifyEnvelope, generateNonce } from "./crypto.js";
import { getContactByPubkey, touchContact, updateContactEndpoint, updateContactInfo, resolveDisplayName, syncAttestationsFromEnvelope } from "./contacts.js";
import { addToInbox } from "./quarantine.js";
import { TrustLevel, type MessageEnvelope, type MessagePayload, type StoredMessage } from "./types.js";

/**
 * Compose, encrypt, sign, and send a message to a contact.
 */
export async function sendMessage(opts: {
  to: string; // recipient pubkey base64
  type: string;
  content: string;
  metadata?: Record<string, unknown>;
}): Promise<{ id: string; status: string; delivered: boolean; timestamp: string; error?: string }> {
  const identity = getIdentity();
  if (!identity) throw new Error("Identity not initialized");

  const contact = getContactByPubkey(opts.to);
  if (!contact) throw new Error("Contact not found");
  // age_public_key is optional — if missing, we derive encryption from the ed25519 key
  const hasAgeKey = !!contact.age_public_key;

  const id = ulid();
  const timestamp = new Date().toISOString();
  const nonce = generateNonce();

  // Build payload
  const payload: MessagePayload = {
    type: opts.type as any,
    content: opts.content,
    metadata: opts.metadata,
  };

  // Encrypt — prefer age key, fall back to SSH ed25519 key
  const payloadJson = JSON.stringify(payload);
  let encryptedPayload: string;
  if (hasAgeKey) {
    encryptedPayload = ageEncrypt(payloadJson, contact.age_public_key!);
  } else {
    // Derive SSH public key from ed25519 key and encrypt with age -R
    const sshPubkey = ed25519ToSshPubkey(contact.public_key);
    encryptedPayload = ageEncryptToSshKey(payloadJson, sshPubkey);
  }

  // Sign
  const signature = signEnvelope(
    identity.privateKey,
    encryptedPayload,
    nonce,
    timestamp
  );

  const envelope: MessageEnvelope = {
    id,
    from: identity.publicKey.toString("base64"),
    to: opts.to,
    type: opts.type as any,
    payload: encryptedPayload,
    signature,
    timestamp,
    nonce,
    sender_name: identity.displayName,
    sender_endpoint: identity.endpoint,
    sender_age_key: identity.agePublicKey,
  };

  // Store locally
  const db = getDb();
  db.prepare(
    `INSERT INTO messages (id, from_key, to_key, type, content, metadata, direction, status, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, 'outgoing', 'delivered', ?)`
  ).run(id, envelope.from, opts.to, opts.type, opts.content, JSON.stringify(opts.metadata || {}), timestamp);

  // Deliver via HTTP POST
  let delivered = false;
  let error: string | undefined;

  try {
    const resp = await fetch(`${contact.endpoint}/messages/receive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
      signal: AbortSignal.timeout(10000),
    });

    if (resp.ok) {
      delivered = true;
    } else {
      error = `HTTP ${resp.status}`;
      // Queue for retry
      queueForRetry(id, opts.to, contact.endpoint, envelope);
    }
  } catch (e: any) {
    error = e.message || "ECONNREFUSED";
    queueForRetry(id, opts.to, contact.endpoint, envelope);
  }

  if (!delivered) {
    db.prepare("UPDATE messages SET status = 'queued' WHERE id = ?").run(id);
  }

  return { id, status: delivered ? "sent" : "queued", delivered, timestamp, error };
}

function queueForRetry(messageId: string, toKey: string, toEndpoint: string, envelope: MessageEnvelope): void {
  const db = getDb();
  const id = ulid();
  const nextRetry = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 min

  db.prepare(
    `INSERT INTO outbound_queue (id, message_id, to_key, to_endpoint, envelope, next_retry_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(id, messageId, toKey, toEndpoint, JSON.stringify(envelope), nextRetry);
}

/**
 * Process an incoming message envelope.
 */
export function receiveMessage(envelope: MessageEnvelope): {
  received: boolean;
  id: string;
  error?: string;
  code?: string;
} {
  const identity = getIdentity();
  if (!identity) return { received: false, id: "", error: "Identity not initialized", code: "INTERNAL" };

  const myPubKey = identity.publicKey.toString("base64");

  // Accept both "to" and "recipient" field names (interop)
  const toKey = (envelope as any).to || (envelope as any).recipient;
  const fromKey = (envelope as any).from || (envelope as any).sender;
  if (!toKey || !fromKey) {
    return { received: false, id: envelope.id, error: "Missing to/from fields", code: "INVALID_ENVELOPE" };
  }

  // Verify recipient matches us
  if (toKey !== myPubKey) {
    return { received: false, id: envelope.id, error: "Wrong recipient", code: "WRONG_RECIPIENT" };
  }

  // Check envelope size (64 KiB)
  const envelopeSize = Buffer.byteLength(JSON.stringify(envelope), "utf-8");
  if (envelopeSize > 65536) {
    return { received: false, id: envelope.id, error: "Payload too large", code: "PAYLOAD_TOO_LARGE" };
  }

  // Verify signature
  if (envelope.signature && envelope.nonce) {
    const valid = verifyEnvelope(fromKey, envelope.payload, envelope.nonce, envelope.timestamp, envelope.signature);
    if (!valid) {
      return { received: false, id: envelope.id, error: "Invalid signature", code: "INVALID_SIGNATURE" };
    }
  }

  // Check replay (nonce dedup)
  const db = getDb();
  if (envelope.nonce) {
    const seen = db.prepare("SELECT 1 FROM seen_nonces WHERE nonce = ?").get(envelope.nonce);
    if (seen) {
      return { received: false, id: envelope.id, error: "Duplicate nonce", code: "DUPLICATE_NONCE" };
    }
    db.prepare("INSERT INTO seen_nonces (nonce, from_key) VALUES (?, ?)").run(envelope.nonce, fromKey);
  }

  // Check timestamp bounds (±5 min for fresh, 24h for queued)
  const msgTime = new Date(envelope.timestamp).getTime();
  const now = Date.now();
  if (msgTime > now + 5 * 60 * 1000) {
    return { received: false, id: envelope.id, error: "Timestamp in future", code: "INVALID_ENVELOPE" };
  }
  if (msgTime < now - 24 * 60 * 60 * 1000) {
    return { received: false, id: envelope.id, error: "Timestamp too old", code: "INVALID_ENVELOPE" };
  }

  // Check trust level
  const contact = getContactByPubkey(fromKey);
  const trustLevel = contact?.trust_level ?? null;

  // Update contact info from envelope metadata (sender_name, sender_endpoint, sender_age_key)
  if (contact) {
    updateContactInfo(fromKey, {
      displayName: (envelope as any).sender_name,
      endpoint: (envelope as any).sender_endpoint,
      agePublicKey: (envelope as any).sender_age_key,
    });

    // Sync attestation URLs from envelope
    if (envelope.attestations?.length) {
      syncAttestationsFromEnvelope(contact.id, envelope.attestations);
    }

    // If contact still missing age_public_key or endpoint, try identity discovery
    const refreshed = getContactByPubkey(fromKey);
    if (refreshed && (!refreshed.age_public_key || refreshed.endpoint === "unknown") && refreshed.endpoint && refreshed.endpoint !== "unknown") {
      // Fire-and-forget identity discovery
      discoverIdentity(refreshed.endpoint, fromKey).catch(() => {});
    }
  }

  // Blocked → silently drop
  if (trustLevel === TrustLevel.BLOCKED) {
    return { received: true, id: envelope.id };
  }

  // Trusted → decrypt and store
  if (trustLevel === TrustLevel.TRUSTED) {
    try {
      const decrypted = ageDecrypt(envelope.payload, identity.agePrivateKey, identity.privateKey);
      const payload: MessagePayload = JSON.parse(decrypted);

      // Store message
      db.prepare(
        `INSERT INTO messages (id, from_key, to_key, type, content, metadata, direction, status, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, 'incoming', 'delivered', ?)`
      ).run(envelope.id, fromKey, toKey, envelope.type, payload.content, JSON.stringify(payload.metadata || {}), envelope.timestamp);

      // Push to inbox
      addToInbox({
        source: "fleet-chat",
        sourceId: fromKey,
        sourceName: contact?.display_name || fromKey.slice(0, 12),
        channel: "direct",
        content: payload.content,
        metadata: payload.metadata,
        originalMessageId: envelope.id,
      });

      // Handle endpoint_migration type
      if (envelope.type === "endpoint_migration" && payload.metadata) {
        const newEndpoint = payload.metadata.new_endpoint as string;
        if (newEndpoint) {
          updateContactEndpoint(fromKey, newEndpoint);
        }
      }

      touchContact(fromKey);
    } catch (e: any) {
      return { received: false, id: envelope.id, error: `Decryption failed: ${e.message}`, code: "DECRYPTION_FAILED" };
    }

    return { received: true, id: envelope.id };
  }

  // Unknown / pending / not in contacts → quarantine
  quarantineMessage(envelope, fromKey);
  return { received: true, id: envelope.id };
}

function quarantineMessage(envelope: MessageEnvelope, fromKey: string): void {
  const db = getDb();
  const id = ulid();

  db.prepare(
    `INSERT INTO quarantine (id, message_id, from_key, envelope, type, status)
     VALUES (?, ?, ?, ?, ?, 'pending')`
  ).run(id, envelope.id, fromKey, JSON.stringify(envelope), envelope.type);

  // Auto-create unknown contact if needed, using sender metadata from envelope
  const contact = getContactByPubkey(fromKey);
  if (!contact) {
    const contactId = ulid();
    const senderEndpoint = envelope.sender_endpoint || "unknown";
    const senderName = envelope.sender_name || null;
    const senderAgeKey = envelope.sender_age_key || null;
    db.prepare(
      `INSERT OR IGNORE INTO contacts (id, public_key, display_name, endpoint, trust_level, age_public_key)
       VALUES (?, ?, ?, ?, 0, ?)`
    ).run(contactId, fromKey, senderName, senderEndpoint, senderAgeKey);

    // Also create contact_keys entry
    const keyId = ulid();
    db.prepare(
      `INSERT OR IGNORE INTO contact_keys (id, contact_id, public_key, key_type, age_public_key)
       VALUES (?, ?, ?, 'ed25519', ?)`
    ).run(keyId, contactId, fromKey, senderAgeKey);

    // Sync attestations from envelope
    if (envelope.attestations?.length) {
      syncAttestationsFromEnvelope(contactId, envelope.attestations);
    }
  } else {
    // Update existing contact with any new info from envelope
    updateContactInfo(fromKey, {
      displayName: envelope.sender_name,
      endpoint: envelope.sender_endpoint,
      agePublicKey: envelope.sender_age_key,
    });
    // Sync attestations
    if (envelope.attestations?.length) {
      syncAttestationsFromEnvelope(contact.id, envelope.attestations);
    }
  }
}

/**
 * Discover a sender's identity by calling GET <endpoint>/identity.
 * Updates the contact record with discovered info.
 */
async function discoverIdentity(endpoint: string, publicKey: string): Promise<boolean> {
  try {
    const resp = await fetch(`${endpoint}/identity`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!resp.ok) return false;

    const data = await resp.json() as {
      public_key?: string;
      age_public_key?: string;
      endpoint?: string;
      display_name?: string;
    };

    // Verify the identity matches the expected public key
    if (data.public_key && data.public_key !== publicKey) return false;

    updateContactInfo(publicKey, {
      displayName: data.display_name,
      endpoint: data.endpoint,
      agePublicKey: data.age_public_key,
    });

    return true;
  } catch {
    return false;
  }
}

/**
 * List messages with filters.
 */
export function listMessages(opts?: {
  with?: string;
  type?: string;
  since?: string;
  before?: string;
  limit?: number;
  offset?: number;
}): { messages: StoredMessage[]; count: number; total: number } {
  const db = getDb();
  let sql = "SELECT * FROM messages WHERE 1=1";
  let countSql = "SELECT COUNT(*) as total FROM messages WHERE 1=1";
  const params: any[] = [];
  const countParams: any[] = [];

  if (opts?.with) {
    const clause = " AND (from_key = ? OR to_key = ?)";
    sql += clause;
    countSql += clause;
    params.push(opts.with, opts.with);
    countParams.push(opts.with, opts.with);
  }

  if (opts?.type) {
    sql += " AND type = ?";
    countSql += " AND type = ?";
    params.push(opts.type);
    countParams.push(opts.type);
  }

  if (opts?.since) {
    sql += " AND timestamp > ?";
    countSql += " AND timestamp > ?";
    params.push(opts.since);
    countParams.push(opts.since);
  }

  if (opts?.before) {
    sql += " AND timestamp < ?";
    countSql += " AND timestamp < ?";
    params.push(opts.before);
    countParams.push(opts.before);
  }

  const total = (db.prepare(countSql).get(...countParams) as any).total;

  const limit = Math.min(opts?.limit || 50, 200);
  const offset = opts?.offset || 0;
  sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);

  const messages = db.prepare(sql).all(...params) as StoredMessage[];

  // Resolve display names for each message
  const messagesWithNames = messages.map((msg) => ({
    ...msg,
    from_name: resolveDisplayName(msg.from_key),
    to_name: resolveDisplayName(msg.to_key),
  }));

  return { messages: messagesWithNames, count: messages.length, total };
}

/**
 * Purge old nonces (24h+).
 */
export function purgeOldNonces(): number {
  const db = getDb();
  const result = db.prepare("DELETE FROM seen_nonces WHERE seen_at < datetime('now', '-24 hours')").run();
  return result.changes;
}
