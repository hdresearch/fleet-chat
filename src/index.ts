import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { streamSSE } from "hono/streaming";
import { getDb, closeDb } from "./store.js";
import { getOrCreateIdentity, getIdentity, getPublicKeyBase64, getOwnAttestations } from "./identity.js";
import { sendMessage, receiveMessage, listMessages, purgeOldNonces } from "./messages.js";
import {
  addContact,
  listContacts,
  getContactByPubkey,
  getContactIdByPubkey,
  setTrustLevel,
  deleteContact,
  generateAddLinkToken,
  consumeAddLinkToken,
  getContactKeys,
  addContactKey,
  removeContactKey,
  getAttestations,
  addAttestation,
  verifyAttestation,
  removeAttestation,
} from "./contacts.js";
import {
  listQuarantine,
  approveQuarantine,
  rejectQuarantine,
  bulkApproveFromSender,
  listInbox,
  getInboxItem,
  markInboxRead,
  archiveInboxItem,
  getUnreadCount,
} from "./quarantine.js";
import { migrateEndpoint } from "./migration.js";
import { TrustLevelName, TrustLevelFromName } from "./types.js";
import { truncateKey, resolveDisplayName } from "./contacts.js";

const app = new Hono();

// ─── Auth middleware ───
const apiToken = process.env.FLEET_CHAT_API_TOKEN;

function requireAuth(c: any, next: () => Promise<void>) {
  // Public endpoints skip auth
  const path = c.req.path;
  if (
    path === "/identity" && c.req.method === "GET" ||
    path === "/messages/receive" && c.req.method === "POST" ||
    path === "/contacts/add-link" && (c.req.method === "GET" || c.req.method === "POST") ||
    path === "/health"
  ) {
    return next();
  }

  if (!apiToken) return next(); // No token configured = no auth

  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({ error: "Unauthorized", code: "UNAUTHORIZED" }, 401);
  }

  const token = authHeader.slice(7);
  if (token !== apiToken) {
    return c.json({ error: "Unauthorized", code: "UNAUTHORIZED" }, 401);
  }

  return next();
}

app.use("*", requireAuth);

// ─── Health ───
app.get("/health", (c) => {
  return c.json({ status: "ok", version: "2.1.0" });
});

// ─── Identity ───
app.get("/identity", (c) => {
  const identity = getIdentity();
  if (!identity) return c.json({ error: "Identity not initialized" }, 500);

  const attestations = getOwnAttestations();

  return c.json({
    // v2.1 format: keys array + attestations
    display_name: identity.displayName,
    endpoint: identity.endpoint,
    keys: [
      {
        public_key: identity.publicKey.toString("base64"),
        key_type: "ed25519",
      },
    ],
    attestations,
    // Keep legacy fields for backward compatibility
    public_key: identity.publicKey.toString("base64"),
    age_public_key: identity.agePublicKey,
    version: "2.1.0",
    capabilities: ["text", "attestations", "endpoint_migration", "key_exchange", "ping", "ack"],
  });
});

app.post("/identity/migrate", async (c) => {
  const body = await c.req.json();
  if (!body.new_endpoint) {
    return c.json({ error: "new_endpoint required" }, 400);
  }

  try {
    const result = await migrateEndpoint(body.new_endpoint, body.reason);
    return c.json({
      migrated: result.migrated,
      old_endpoint: result.oldEndpoint,
      new_endpoint: result.newEndpoint,
      notifications_sent: result.notificationsSent,
      notifications_failed: result.notificationsFailed,
      failed_contacts: result.failedContacts,
    });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// ─── Messages ───
app.post("/messages/send", async (c) => {
  const body = await c.req.json();
  if (!body.to || !body.content) {
    return c.json({ error: "to and content required" }, 400);
  }

  try {
    const result = await sendMessage({
      to: body.to,
      type: body.type || "text",
      content: body.content,
      metadata: body.metadata,
    });
    return c.json(result);
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

app.get("/messages", (c) => {
  const result = listMessages({
    with: c.req.query("with"),
    type: c.req.query("type"),
    since: c.req.query("since"),
    before: c.req.query("before"),
    limit: c.req.query("limit") ? parseInt(c.req.query("limit")!) : undefined,
    offset: c.req.query("offset") ? parseInt(c.req.query("offset")!) : undefined,
  });
  return c.json(result);
});

app.post("/messages/receive", async (c) => {
  const envelope = await c.req.json();

  if (!envelope.id || !envelope.payload) {
    return c.json({ error: "Invalid envelope", code: "INVALID_ENVELOPE" }, 400);
  }

  const result = receiveMessage(envelope);

  if (!result.received) {
    const code = result.code || "";
    if (code === "INVALID_SIGNATURE") {
      return c.json({ error: result.error, code: result.code }, 401);
    } else if (code === "DUPLICATE_NONCE") {
      return c.json({ error: result.error, code: result.code }, 409);
    } else if (code === "PAYLOAD_TOO_LARGE") {
      return c.json({ error: result.error, code: result.code }, 413);
    } else if (code === "DECRYPTION_FAILED") {
      return c.json({ error: result.error, code: result.code }, 500);
    } else {
      return c.json({ error: result.error, code: result.code }, 400);
    }
  }

  return c.json({ received: true, id: result.id });
});

// ─── SSE Stream ───
app.get("/stream", (c) => {
  return streamSSE(c, async (stream) => {
    // Send initial ping
    await stream.writeSSE({ event: "ping", data: JSON.stringify({ timestamp: new Date().toISOString() }) });

    // Keep alive with pings every 30s
    const interval = setInterval(async () => {
      try {
        await stream.writeSSE({ event: "ping", data: JSON.stringify({ timestamp: new Date().toISOString() }) });
      } catch {
        clearInterval(interval);
      }
    }, 30000);

    // Wait until connection closes
    await new Promise((resolve) => {
      stream.onAbort(() => {
        clearInterval(interval);
        resolve(undefined);
      });
    });
  });
});

// ─── Contacts ───
app.get("/contacts", (c) => {
  const contacts = listContacts({
    trustLevel: c.req.query("trust_level"),
    search: c.req.query("search"),
  });

  return c.json({
    contacts: contacts.map((ct) => {
      const keys = getContactKeys(ct.id);
      const attestationList = getAttestations(ct.id);
      return {
        ...ct,
        trust_level: TrustLevelName[ct.trust_level] || "unknown",
        display_name: ct.display_name || truncateKey(ct.public_key || "unknown"),
        keys: keys.map((k) => ({
          id: k.id,
          public_key: k.public_key,
          key_type: k.key_type,
          age_public_key: k.age_public_key,
          added_at: k.added_at,
          last_used: k.last_used,
        })),
        attestations: attestationList.map((a) => ({
          id: a.id,
          url: a.url,
          status: a.status,
          verified_at: a.verified_at,
          verified_by: a.verified_by,
        })),
      };
    }),
    count: contacts.length,
  });
});

app.post("/contacts/add", async (c) => {
  const body = await c.req.json();
  if (!body.public_key || !body.endpoint) {
    return c.json({ error: "public_key and endpoint required" }, 400);
  }

  try {
    const contact = addContact({
      publicKey: body.public_key,
      endpoint: body.endpoint,
      displayName: body.display_name,
      trustLevel: body.trust_level,
      agePublicKey: body.age_public_key,
      notes: body.notes,
      attestations: body.attestations,
    });
    return c.json({
      ...contact,
      trust_level: TrustLevelName[contact.trust_level] || "unknown",
      keys: getContactKeys(contact.id),
      attestations: getAttestations(contact.id),
    }, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

app.post("/contacts/trust", async (c) => {
  const body = await c.req.json();
  if (!body.public_key || !body.trust_level) {
    return c.json({ error: "public_key and trust_level required" }, 400);
  }

  const result = setTrustLevel(body.public_key, body.trust_level);
  if (!result) {
    return c.json({ error: "Contact not found or invalid trust level", code: "CONTACT_NOT_FOUND" }, 404);
  }

  return c.json({
    public_key: body.public_key,
    display_name: result.contact.display_name,
    old_trust_level: result.oldLevel,
    new_trust_level: result.newLevel,
  });
});

app.delete("/contacts/:pubkey", (c) => {
  const pubkey = c.req.param("pubkey");
  const deleted = deleteContact(pubkey);
  return deleted ? c.json({ deleted: true }) : c.json({ error: "Not found" }, 404);
});

// ─── Friend-add links ───
app.post("/contacts/generate-add-link", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const expiresInHours = body.expires_in_hours || 24;

  const identity = getIdentity();
  if (!identity) return c.json({ error: "Identity not initialized" }, 500);

  const { token, expiresAt } = generateAddLinkToken(expiresInHours);
  const url = `${identity.endpoint}/contacts/add-link?pubkey=${encodeURIComponent(identity.publicKey.toString("base64"))}&endpoint=${encodeURIComponent(identity.endpoint)}&name=${encodeURIComponent(identity.displayName)}&token=${token}`;

  return c.json({ url, token, expires_at: expiresAt });
});

app.get("/contacts/add-link", (c) => {
  const token = c.req.query("token");
  const pubkey = c.req.query("pubkey");

  if (!token) return c.json({ error: "Token required" }, 400);

  // Don't consume the token on GET — just validate it, show our identity
  // Token is consumed on POST (the actual exchange)
  const db = getDb();
  const tokenRow = db.prepare(
    "SELECT * FROM add_link_tokens WHERE token = ? AND used = 0 AND expires_at > datetime('now')"
  ).get(token) as any;
  if (!tokenRow) return c.json({ error: "Invalid or expired token" }, 400);

  const identity = getIdentity();
  if (!identity) return c.json({ error: "Identity not initialized" }, 500);

  // If the visitor provided their info via query params (legacy), add as pending contact
  const visitorPubkey = c.req.query("visitor_pubkey");
  const visitorEndpoint = c.req.query("visitor_endpoint");
  const visitorName = c.req.query("visitor_name");
  const visitorAgeKey = c.req.query("visitor_age_key");

  if (visitorPubkey && visitorEndpoint) {
    try {
      addContact({
        publicKey: visitorPubkey,
        endpoint: visitorEndpoint,
        displayName: visitorName || undefined,
        trustLevel: "pending",
        agePublicKey: visitorAgeKey || undefined,
      });
    } catch {
      // Already exists, that's fine
    }
    // Consume token on successful exchange
    consumeAddLinkToken(token, visitorPubkey);
  }

  const attestations = getOwnAttestations();

  return c.json({
    public_key: identity.publicKey.toString("base64"),
    endpoint: identity.endpoint,
    display_name: identity.displayName,
    age_public_key: identity.agePublicKey,
    attestations,
    // Tell the visitor to POST back their identity for mutual exchange
    exchange_url: `${identity.endpoint}/contacts/add-link`,
  });
});

// POST /contacts/add-link — bidirectional identity exchange
// The visitor POSTs their identity to complete the mutual add
app.post("/contacts/add-link", async (c) => {
  const body = await c.req.json();
  const token = body.token || c.req.query("token");

  if (!token) return c.json({ error: "Token required" }, 400);

  const valid = consumeAddLinkToken(token, body.public_key);
  if (!valid) return c.json({ error: "Invalid or expired token" }, 400);

  if (!body.public_key || !body.endpoint) {
    return c.json({ error: "public_key and endpoint required" }, 400);
  }

  const identity = getIdentity();
  if (!identity) return c.json({ error: "Identity not initialized" }, 500);

  // Add the visitor as a pending contact with full info
  try {
    addContact({
      publicKey: body.public_key,
      endpoint: body.endpoint,
      displayName: body.display_name || undefined,
      trustLevel: "pending",
      agePublicKey: body.age_public_key || undefined,
      attestations: body.attestations,
    });
  } catch {
    // Already exists — update their info if we have better data
    const { updateContactInfo, syncAttestationsFromEnvelope, getContactIdByPubkey: getIdByPk } = await import("./contacts.js");
    updateContactInfo(body.public_key, {
      displayName: body.display_name,
      endpoint: body.endpoint,
      agePublicKey: body.age_public_key,
    });
    if (body.attestations?.length) {
      const cid = getIdByPk(body.public_key);
      if (cid) syncAttestationsFromEnvelope(cid, body.attestations);
    }
  }

  const attestations = getOwnAttestations();

  // Return our full identity so both sides have complete records
  return c.json({
    public_key: identity.publicKey.toString("base64"),
    endpoint: identity.endpoint,
    display_name: identity.displayName,
    age_public_key: identity.agePublicKey,
    attestations,
    added: true,
  });
});

// ─── Contact keys ───
app.get("/contacts/:contactId/keys", (c) => {
  const contactId = c.req.param("contactId");
  const keys = getContactKeys(contactId);
  return c.json({ keys, count: keys.length });
});

app.post("/contacts/:contactId/keys", async (c) => {
  const contactId = c.req.param("contactId");
  const body = await c.req.json();
  if (!body.public_key) return c.json({ error: "public_key required" }, 400);

  try {
    const key = addContactKey(contactId, {
      publicKey: body.public_key,
      keyType: body.key_type,
      agePublicKey: body.age_public_key,
    });
    return c.json(key, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

app.delete("/contacts/keys/:keyId", (c) => {
  const keyId = c.req.param("keyId");
  const deleted = removeContactKey(keyId);
  return deleted ? c.json({ deleted: true }) : c.json({ error: "Not found" }, 404);
});

// ─── Attestations ───
app.get("/contacts/:contactId/attestations", (c) => {
  const contactId = c.req.param("contactId");
  const attestations = getAttestations(contactId);
  return c.json({ attestations, count: attestations.length });
});

app.post("/contacts/:contactId/attestations", async (c) => {
  const contactId = c.req.param("contactId");
  const body = await c.req.json();
  if (!body.url) return c.json({ error: "url required" }, 400);

  try {
    const attestation = addAttestation(contactId, body.url, { notes: body.notes });
    return c.json(attestation, 201);
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

app.post("/contacts/attestations/:attestationId/verify", async (c) => {
  const attestationId = c.req.param("attestationId");
  const body = await c.req.json();
  if (!body.status || !["verified", "rejected"].includes(body.status)) {
    return c.json({ error: "status must be 'verified' or 'rejected'" }, 400);
  }

  const result = verifyAttestation(attestationId, {
    status: body.status,
    verifiedBy: body.verified_by || "api",
    notes: body.notes,
  });

  return result
    ? c.json(result)
    : c.json({ error: "Not found" }, 404);
});

app.delete("/contacts/attestations/:attestationId", (c) => {
  const attestationId = c.req.param("attestationId");
  const deleted = removeAttestation(attestationId);
  return deleted ? c.json({ deleted: true }) : c.json({ error: "Not found" }, 404);
});

// ─── Quarantine ───
app.get("/quarantine", (c) => {
  const result = listQuarantine({
    status: c.req.query("status"),
    from: c.req.query("from"),
    limit: c.req.query("limit") ? parseInt(c.req.query("limit")!) : undefined,
  });

  return c.json({
    items: result.items.map((item) => {
      const contactId = getContactIdByPubkey(item.from_key);
      const attestationList = contactId ? getAttestations(contactId) : [];
      return {
        id: item.id,
        message_id: item.message_id,
        from_key: item.from_key,
        from_name: resolveDisplayName(item.from_key),
        attestations: attestationList.map((a) => ({
          url: a.url,
          status: a.status,
        })),
        received_at: item.received_at,
        type: item.type,
        status: item.status,
      };
    }),
    count: result.count,
  });
});

app.post("/quarantine/:id/approve", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => ({}));

  const result = approveQuarantine(id, {
    setTrust: body.set_trust,
    reviewedBy: body.reviewed_by,
  });

  if (!result.approved) {
    return c.json({ error: result.error }, 400);
  }

  return c.json({
    approved: true,
    message_id: result.messageId,
    inbox_id: result.inboxId,
    sender_trust_updated: result.senderTrustUpdated,
  });
});

app.post("/quarantine/:id/reject", async (c) => {
  const id = c.req.param("id");
  const body = await c.req.json().catch(() => ({}));

  const result = rejectQuarantine(id, {
    blockSender: body.block_sender,
    reviewedBy: body.reviewed_by,
  });

  if (!result.rejected) {
    return c.json({ error: result.error }, 400);
  }

  return c.json({
    rejected: true,
    message_id: result.messageId,
    sender_blocked: result.senderBlocked,
  });
});

app.post("/quarantine/approve-all", async (c) => {
  const fromKey = c.req.query("from");
  if (!fromKey) return c.json({ error: "from query param required" }, 400);

  const body = await c.req.json().catch(() => ({}));
  const result = bulkApproveFromSender(fromKey, { setTrust: body.set_trust });
  return c.json(result);
});

// ─── Inbox ───
app.get("/inbox", (c) => {
  const result = listInbox({
    channel: c.req.query("channel"),
    read: c.req.query("read") ? c.req.query("read") === "true" : undefined,
    archived: c.req.query("archived") ? c.req.query("archived") === "true" : undefined,
    since: c.req.query("since"),
    limit: c.req.query("limit") ? parseInt(c.req.query("limit")!) : undefined,
  });

  return c.json({ items: result.items, count: result.count, unread: result.unread });
});

app.get("/inbox/unread-count", (c) => {
  return c.json(getUnreadCount());
});

app.get("/inbox/:id", (c) => {
  const item = getInboxItem(c.req.param("id"));
  return item ? c.json(item) : c.json({ error: "Not found" }, 404);
});

app.post("/inbox/:id/read", (c) => {
  const ok = markInboxRead(c.req.param("id"));
  return ok ? c.json({ read: true }) : c.json({ error: "Not found" }, 404);
});

app.post("/inbox/:id/archive", (c) => {
  const ok = archiveInboxItem(c.req.param("id"));
  return ok ? c.json({ archived: true }) : c.json({ error: "Not found" }, 404);
});

// ─── Startup ───
async function main() {
  const port = parseInt(process.env.FLEET_CHAT_PORT || "3847");
  const host = process.env.FLEET_CHAT_HOST || "0.0.0.0";

  // Initialize DB and identity
  getDb();
  const identity = getOrCreateIdentity();

  console.log(`[fleet-chat] Identity: ${identity.publicKey.toString("base64")}`);
  console.log(`[fleet-chat] Age key:  ${identity.agePublicKey}`);
  console.log(`[fleet-chat] Endpoint: ${identity.endpoint}`);

  // Periodic nonce cleanup (every hour)
  setInterval(() => {
    try { purgeOldNonces(); } catch {}
  }, 60 * 60 * 1000);

  serve({ fetch: app.fetch, port, hostname: host }, (info) => {
    console.log(`[fleet-chat] Listening on ${host}:${info.port}`);
  });
}

main().catch((e) => {
  console.error("[fleet-chat] Fatal:", e);
  process.exit(1);
});

export { app };
