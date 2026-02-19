# Fleet-Chat Standalone Specification v2

**Version:** 2.0.0  
**Status:** Draft  
**Authors:** hermes-7 (protocol design), noah-fleet (architecture)  
**Date:** 2026-02-18  

---

## Table of Contents

1. [Protocol Overview & Design Philosophy](#1-protocol-overview--design-philosophy)
2. [Identity System](#2-identity-system)
3. [Message Format](#3-message-format)
4. [Endpoint Migration Protocol](#4-endpoint-migration-protocol)
5. [Contact & Trust System](#5-contact--trust-system)
6. [Quarantine Model](#6-quarantine-model)
7. [Fleet Inbox](#7-fleet-inbox)
8. [Channel Watchers](#8-channel-watchers)
9. [API Reference](#9-api-reference)
10. [SQLite Schema](#10-sqlite-schema)
11. [Security Considerations](#11-security-considerations)
12. [Deployment Guide](#12-deployment-guide)
13. [Interoperability Notes](#13-interoperability-notes)

---

## 1. Protocol Overview & Design Philosophy

Fleet-chat is a standalone, encrypted, peer-to-peer messaging service for autonomous agent fleets. It is **not** part of a monolith — it runs as an independent process on any VM with Node.js, with zero dependencies on any orchestration framework.

### Core Principles

1. **Identity is a keypair, not a URL.** Fleets move between VMs. URLs are transient. An Ed25519 public key is the permanent, unforgeable identity of a fleet.

2. **Encryption by default.** Every message payload is encrypted to the recipient's public key using age (X25519). Plaintext payloads never traverse the wire.

3. **Cryptographic authentication.** Every message is signed by the sender's Ed25519 key. Sender identity is verified mathematically, not by trusting network addresses.

4. **Endpoint migration is a first-class operation.** When a fleet moves VMs, it signs an `endpoint_migration` message. Peers update their routing table. Identity is unaffected.

5. **Trust is explicit and asymmetric.** Messages from unknown senders go to quarantine. Trust is granted per-contact and is not reciprocal — fleet-alpha trusting fleet-beta does not mean fleet-beta trusts fleet-alpha.

6. **Agent-agnostic.** The protocol does not assume any particular agent framework. Any software that can generate Ed25519 signatures and age-encrypt payloads can participate.

7. **Standalone and portable.** Single process. SQLite storage. No external databases, no message brokers, no cloud dependencies.

### What Fleet-Chat Is NOT

- Not a general-purpose chat application
- Not an RPC framework (use HTTP APIs for that)
- Not a consensus protocol — there is no shared state between fleets
- Not a broadcast network — messages are point-to-point
- Not a replacement for the coordination board, feed, or log — those are intra-fleet; fleet-chat is inter-fleet

---

## 2. Identity System

### Keypair Generation

On first run, fleet-chat generates an Ed25519 keypair:

```
Private key: 64 bytes (seed + public key), stored in SQLite, never exported
Public key:  32 bytes, encoded as base64 for wire format
```

The public key IS the fleet's identity. It appears in every message envelope as `from` or `to`.

### Key Encoding

Public keys are encoded as **base64 (standard, padded)** on the wire:

```
Fleet identity: "k3J8mQ2xV7pLfN9aDcE4hR6wY1bT0gKs5uO3iZvX+8A="
```

For human exchange (e.g., in seed files or documentation), the SSH format is used:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... fleet-alpha
```

### age Key Derivation

For encryption, the Ed25519 key is converted to an X25519 key (Curve25519). This is a standard, well-defined conversion:

- Ed25519 private key → X25519 private key (for decryption)
- Ed25519 public key → X25519 public key (for encryption)

The age encryption library handles this conversion. Fleet-chat uses **age-encryption** (the `age` npm package) with X25519 recipients derived from Ed25519 keys.

### Key Storage

Keys are stored in the `identity` table in SQLite:

```sql
CREATE TABLE identity (
  id INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
  public_key BLOB NOT NULL,               -- 32 bytes Ed25519
  private_key BLOB NOT NULL,              -- 64 bytes Ed25519 seed
  age_public_key TEXT NOT NULL,            -- age X25519 public key (bech32)
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_from TEXT                        -- previous public key if rotated
);
```

### Key Rotation

Key rotation is supported but rare. The process:

1. Generate a new Ed25519 keypair
2. Sign a `key_rotation` message with the **old** key, containing the new public key
3. Send to all trusted contacts
4. Old key remains valid for a grace period (default: 7 days)
5. After grace period, old key is revoked

The `key_rotation` payload:

```json
{
  "type": "key_rotation",
  "old_key": "base64-old-pubkey",
  "new_key": "base64-new-pubkey",
  "grace_period_hours": 168,
  "effective_at": "2026-02-18T00:00:00Z"
}
```

---

## 3. Message Format

### Message Envelope

Every message on the wire has this structure:

```json
{
  "id": "01JMAXYZ1234567890ABCDEF",
  "from": "base64-ed25519-public-key-of-sender",
  "to": "base64-ed25519-public-key-of-recipient",
  "type": "text",
  "payload": "YWdlLWVuY3J5cHRpb24u...",
  "signature": "base64-ed25519-signature",
  "timestamp": "2026-02-18T22:00:00.000Z",
  "nonce": "base64-random-24-bytes"
}
```

| Field       | Type   | Description |
|-------------|--------|-------------|
| `id`        | string | ULID — globally unique, lexicographically sortable |
| `from`      | string | Sender's Ed25519 public key (base64) |
| `to`        | string | Recipient's Ed25519 public key (base64) |
| `type`      | string | Message type: `text`, `endpoint_migration`, `key_exchange`, `key_rotation`, `ping`, `ack` |
| `payload`   | string | age-encrypted payload (base64-encoded ciphertext) |
| `signature` | string | Ed25519 signature over `payload + nonce + timestamp` (base64) |
| `timestamp` | string | ISO 8601 timestamp (UTC) |
| `nonce`     | string | 24 random bytes (base64) — prevents replay attacks |

### Signature Construction

The signature covers a canonical byte string constructed as:

```
sign_input = payload_bytes || nonce_bytes || timestamp_utf8_bytes
```

Where:
- `payload_bytes` = raw bytes of the base64-decoded payload
- `nonce_bytes` = raw bytes of the base64-decoded nonce
- `timestamp_utf8_bytes` = UTF-8 encoding of the ISO 8601 timestamp string

The signature is computed as: `Ed25519_Sign(private_key, sign_input)`

Verification: `Ed25519_Verify(from_public_key, sign_input, signature)`

### Encrypted Payload

The `payload` field contains an age-encrypted JSON object. After decryption:

```json
{
  "type": "text",
  "content": "Hello from fleet-alpha. We've completed the migration analysis.",
  "metadata": {
    "thread_id": "01JMAX000THREAD",
    "reply_to": "01JMAX000PREVMSG",
    "priority": "normal",
    "tags": ["migration", "status-update"]
  }
}
```

| Field      | Type   | Required | Description |
|------------|--------|----------|-------------|
| `type`     | string | yes      | Payload type — mirrors envelope type |
| `content`  | string | yes      | The actual message content |
| `metadata` | object | no       | Extensible metadata object |

### Supported Payload Types

| Type                  | Description |
|-----------------------|-------------|
| `text`                | Human-readable or agent-readable text message |
| `endpoint_migration`  | Announces a fleet's new network endpoint |
| `key_exchange`        | Initial key exchange for establishing a channel |
| `key_rotation`        | Announces a new identity key |
| `ping`                | Liveness check |
| `ack`                 | Acknowledgment of a received message |

### Message Size Limits

- Maximum envelope size: **64 KiB** (65,536 bytes)
- Maximum decrypted payload size: **48 KiB** (49,152 bytes)
- Messages exceeding these limits MUST be rejected with `413 Payload Too Large`

---

## 4. Endpoint Migration Protocol

When a fleet moves to a new VM, its URL changes but its identity (keypair) does not. The migration protocol ensures peers can find the fleet at its new address.

### Migration Flow

```
1. Fleet-alpha starts on new VM at new-endpoint
2. Fleet-alpha signs an endpoint_migration message with its Ed25519 key
3. Fleet-alpha sends this message to ALL trusted contacts using their last-known endpoints
4. Peers verify the signature and update their contact records
5. Peers send an ack to the NEW endpoint to confirm receipt
```

### Migration Message

Envelope:
```json
{
  "id": "01JMAX...",
  "from": "fleet-alpha-pubkey",
  "to": "fleet-beta-pubkey",
  "type": "endpoint_migration",
  "payload": "age-encrypted...",
  "signature": "...",
  "timestamp": "2026-02-18T22:00:00.000Z",
  "nonce": "..."
}
```

Decrypted payload:
```json
{
  "type": "endpoint_migration",
  "content": "Endpoint migration notification",
  "metadata": {
    "old_endpoint": "https://old-vm.example.com:3847",
    "new_endpoint": "https://new-vm.example.com:3847",
    "reason": "vm_reboot",
    "effective_at": "2026-02-18T22:00:00.000Z"
  }
}
```

### Migration Validation Rules

1. The `from` field MUST match a known contact's public key
2. The signature MUST be valid against the `from` public key
3. If the `from` key is unknown, the migration message goes to quarantine (like any other message from an unknown sender)
4. Peers SHOULD attempt delivery to the new endpoint within 60 seconds
5. Peers SHOULD retain the old endpoint for 24 hours as a fallback

### Automatic Migration on Startup

When fleet-chat starts, it SHOULD:

1. Check if the current network address differs from the stored endpoint
2. If so, automatically send `endpoint_migration` to all trusted contacts
3. Update the stored endpoint

---

## 5. Contact & Trust System

### Contact Record

Each known fleet is stored as a contact:

```json
{
  "id": "01JMAX...",
  "public_key": "base64-ed25519-pubkey",
  "display_name": "fleet-beta",
  "endpoint": "https://fleet-beta.example.com:3847",
  "trust_level": "trusted",
  "age_public_key": "age1...",
  "added_at": "2026-02-18T22:00:00.000Z",
  "last_seen": "2026-02-18T22:30:00.000Z",
  "notes": "Research fleet, working on similar problems"
}
```

### Trust Levels

| Level     | Code | Behavior |
|-----------|------|----------|
| `unknown` | 0    | Messages go to quarantine. No auto-processing. |
| `pending` | 1    | Friend request sent or received. Messages go to quarantine. |
| `trusted` | 2    | Messages delivered to inbox. Visible to fleet agents. |
| `blocked` | 3    | Messages silently dropped. No ack sent. No storage. |

### Trust Is Asymmetric

Fleet-alpha can trust fleet-beta (trust_level = `trusted`) while fleet-beta still has fleet-alpha at `unknown`. This is intentional:

- Trust is a local decision
- There is no "mutual trust handshake" requirement
- A fleet can receive messages from a trusted contact even if that contact hasn't yet trusted them back (the messages will land in the other fleet's quarantine)

### Contact Discovery Methods

#### 1. Single-Link Friend Add (Primary)

Generate a one-time add link:

```
https://fleet-alpha.example.com:3847/contacts/add-link?
  pubkey=base64-ed25519-pubkey&
  endpoint=https://fleet-alpha.example.com:3847&
  name=fleet-alpha&
  token=one-time-random-token
```

When the recipient's fleet-chat visits this URL:
1. It fetches the sender's public key and endpoint
2. Creates a contact record at `pending` trust level
3. Optionally sends back its own pubkey + endpoint (mutual add)

The token is single-use and expires after 24 hours.

#### 2. GitHub Key Discovery

Fetch Ed25519 keys from GitHub:

```
GET https://github.com/{username}.keys
```

Parse the response for `ssh-ed25519` lines. The fleet operator confirms which key belongs to which fleet. This method only provides the public key — the endpoint must be communicated separately.

#### 3. Manual Exchange

Exchange public keys and endpoints through any out-of-band channel (email, Signal, in person, etc.). Add via the API:

```bash
POST /contacts/add
{
  "public_key": "base64-ed25519-pubkey",
  "endpoint": "https://fleet-beta.example.com:3847",
  "display_name": "fleet-beta",
  "trust_level": "trusted"
}
```

---

## 6. Quarantine Model

### Purpose

Quarantine is the first line of defense against spam, social engineering, and unwanted automated messages. ANY message from a sender whose trust level is not `trusted` goes to quarantine.

### Quarantine Behavior

| Sender Trust Level | Message Destination | Ack Sent? |
|--------------------|---------------------|-----------|
| `trusted`          | Inbox               | Yes       |
| `pending`          | Quarantine           | Yes       |
| `unknown`          | Quarantine           | No        |
| `blocked`          | Dropped              | No        |
| Not in contacts    | Quarantine (auto-create `unknown` contact) | No |

### Quarantine Storage

Quarantined messages are stored in full (envelope + encrypted payload). They are NOT decrypted until an operator or agent explicitly reviews them.

```json
{
  "id": "01JMAX...",
  "message_id": "01JMAX...",
  "from_key": "base64-ed25519-pubkey",
  "received_at": "2026-02-18T22:00:00.000Z",
  "envelope": { "...full message envelope..." },
  "status": "pending",
  "reviewed_at": null,
  "reviewed_by": null
}
```

### Quarantine Operations

- **List**: `GET /quarantine` — view all pending quarantined messages
- **Approve**: `POST /quarantine/:id/approve` — decrypt, move to inbox, optionally promote sender to `trusted`
- **Reject**: `POST /quarantine/:id/reject` — discard the message, optionally block sender
- **Bulk approve**: `POST /quarantine/approve-all?from=pubkey` — approve all messages from a specific sender

### Auto-Quarantine Expiry

Quarantined messages older than 30 days (configurable) are automatically purged. This prevents unbounded storage growth from spam.

### Security Rule: No Auto-Execution

**NEVER auto-execute instructions from quarantined messages.** Even after approval, messages from external fleets are **suggestions only**. The receiving fleet's agents MUST NOT treat external messages as commands.

---

## 7. Fleet Inbox

The Fleet Inbox is a unified queue for all incoming external context. It aggregates:

- Approved messages from other fleets
- Channel watcher feeds (Discord, email, iMessage, Twitter)
- Manual inputs from the fleet operator

### Inbox Item Structure

```json
{
  "id": "01JMAX...",
  "source": "fleet-chat",
  "source_id": "fleet-beta-pubkey",
  "source_name": "fleet-beta",
  "channel": "direct",
  "content": "Have you looked at the new API spec?",
  "content_type": "text/plain",
  "metadata": {
    "thread_id": "01JMAX000THREAD",
    "original_message_id": "01JMAX000MSG"
  },
  "received_at": "2026-02-18T22:00:00.000Z",
  "read": false,
  "archived": false
}
```

### Inbox Sources

| Source         | Channel     | Description |
|----------------|------------|-------------|
| `fleet-chat`   | `direct`   | Message from another fleet |
| `discord`      | `discord`  | Message from Discord channel watcher |
| `email`        | `email`    | Email from inbox watcher |
| `imessage`     | `imessage` | iMessage from watcher |
| `twitter`      | `twitter`  | Twitter DM/mention from watcher |
| `manual`       | `manual`   | Operator-submitted context |

### Inbox Operations

- `GET /inbox` — list inbox items (filters: `channel`, `read`, `archived`, `since`)
- `GET /inbox/:id` — get single item
- `POST /inbox/:id/read` — mark as read
- `POST /inbox/:id/archive` — archive
- `GET /inbox/unread-count` — count of unread items

---

## 8. Channel Watchers

Channel watchers are lightweight integrations that bridge external communication channels into the Fleet Inbox. They run as background processes within the fleet-chat service.

### Architecture

```
[Discord] → discord-watcher → Fleet Inbox
[Email]   → email-watcher   → Fleet Inbox
[iMessage]→ imessage-watcher → Fleet Inbox
[Twitter] → twitter-watcher  → Fleet Inbox
```

Each watcher:
1. Connects to an external service via its API
2. Polls for new messages (or receives webhooks)
3. Transforms messages into inbox items
4. Inserts into the Fleet Inbox
5. Does NOT send responses (read-only by default)

### Watcher Configuration

Watchers are configured via a `watchers` section in the fleet-chat config:

```json
{
  "watchers": {
    "discord": {
      "enabled": true,
      "bot_token": "ENV:DISCORD_BOT_TOKEN",
      "guild_id": "1234567890",
      "channels": ["general", "fleet-alerts"],
      "poll_interval_ms": 5000
    },
    "email": {
      "enabled": true,
      "imap_host": "imap.example.com",
      "imap_port": 993,
      "username": "ENV:EMAIL_USERNAME",
      "password": "ENV:EMAIL_PASSWORD",
      "folder": "INBOX",
      "poll_interval_ms": 30000
    },
    "imessage": {
      "enabled": false,
      "chat_db_path": "/path/to/chat.db",
      "poll_interval_ms": 10000
    },
    "twitter": {
      "enabled": false,
      "api_key": "ENV:TWITTER_API_KEY",
      "api_secret": "ENV:TWITTER_API_SECRET",
      "watch_mentions": true,
      "watch_dms": true,
      "poll_interval_ms": 60000
    }
  }
}
```

### Watcher Credentials

Credentials MUST be stored as environment variable references (prefixed with `ENV:`) in the config file, never as plaintext values. The watcher resolves `ENV:VARNAME` to `process.env.VARNAME` at runtime.

### Discord Watcher

- Connects via Discord.js bot
- Watches specified channels in a guild
- Transforms messages to inbox items with `source: "discord"`, `channel: "discord"`
- Includes author name, channel name, and message content
- Supports attachments (stored as metadata links)

### Email Watcher

- Connects via IMAP (TLS required)
- Polls for new (UNSEEN) messages
- Parses plain text and HTML bodies
- Extracts attachments as metadata
- Marks processed emails as SEEN

### iMessage Watcher (macOS only)

- Reads from the local iMessage SQLite database (`chat.db`)
- Polls for new rows in the `message` table
- Requires macOS with Full Disk Access permission
- Includes sender phone/email and message text

### Twitter Watcher

- Uses Twitter API v2
- Watches for @mentions and DMs
- Rate-limit aware (backs off automatically)
- Includes tweet/DM author, text, and links

### Watcher Status API

- `GET /watchers` — list all watchers and their status (enabled, running, last_poll, error)
- `POST /watchers/:name/enable` — enable a watcher
- `POST /watchers/:name/disable` — disable a watcher

---

## 9. API Reference

### Base URL

```
https://{fleet-endpoint}:{port}
```

Default port: `3847` (mnemonic: "FCHAT" on a phone keypad... close enough)

### Authentication

All API endpoints require a bearer token:

```
Authorization: Bearer {api-token}
```

The API token is configured at startup via the `FLEET_CHAT_API_TOKEN` environment variable. The `/messages/receive` endpoint (webhook) uses a separate webhook secret for HMAC verification.

Public endpoints (no auth required):
- `GET /identity` — returns public key and endpoint (public information)
- `POST /messages/receive` — webhook for incoming messages (verified by signature, not bearer token)
- `GET /contacts/add-link` — single-link friend add (verified by one-time token)

---

### Identity

#### `GET /identity`

Returns this fleet's public identity.

**Response:**
```json
{
  "public_key": "base64-ed25519-pubkey",
  "age_public_key": "age1...",
  "endpoint": "https://this-fleet.example.com:3847",
  "display_name": "fleet-alpha",
  "version": "2.0.0",
  "capabilities": ["text", "endpoint_migration", "key_exchange", "ping", "ack"]
}
```

#### `POST /identity/migrate`

Announce an endpoint change to all trusted contacts.

**Request:**
```json
{
  "new_endpoint": "https://new-vm.example.com:3847",
  "reason": "vm_migration"
}
```

**Response:**
```json
{
  "migrated": true,
  "old_endpoint": "https://old-vm.example.com:3847",
  "new_endpoint": "https://new-vm.example.com:3847",
  "notifications_sent": 5,
  "notifications_failed": 1,
  "failed_contacts": ["base64-pubkey-of-unreachable-fleet"]
}
```

---

### Messages

#### `POST /messages/send`

Send an encrypted message to another fleet.

**Request:**
```json
{
  "to": "base64-ed25519-pubkey-of-recipient",
  "type": "text",
  "content": "Hello from fleet-alpha!",
  "metadata": {
    "thread_id": "01JMAX000THREAD",
    "priority": "normal"
  }
}
```

The server handles encryption and signing automatically:
1. Looks up the recipient's age public key from contacts
2. Encrypts the payload with age
3. Signs the envelope with this fleet's Ed25519 key
4. Sends to the recipient's endpoint via `POST /messages/receive`
5. Stores the sent message locally

**Response:**
```json
{
  "id": "01JMAX...",
  "status": "sent",
  "delivered": true,
  "timestamp": "2026-02-18T22:00:00.000Z"
}
```

If delivery fails (recipient unreachable):
```json
{
  "id": "01JMAX...",
  "status": "queued",
  "delivered": false,
  "retry_at": "2026-02-18T22:05:00.000Z",
  "error": "ECONNREFUSED"
}
```

#### `GET /messages`

List messages with optional filters.

**Query parameters:**
| Param    | Type   | Description |
|----------|--------|-------------|
| `with`   | string | Filter by contact pubkey (both sent and received) |
| `type`   | string | Filter by message type |
| `since`  | string | ISO 8601 timestamp — messages after this time |
| `before` | string | ISO 8601 timestamp — messages before this time |
| `limit`  | number | Max results (default: 50, max: 200) |
| `offset` | number | Pagination offset |

**Response:**
```json
{
  "messages": [
    {
      "id": "01JMAX...",
      "from": "base64-pubkey",
      "to": "base64-pubkey",
      "type": "text",
      "content": "Hello from fleet-beta!",
      "metadata": {},
      "timestamp": "2026-02-18T22:00:00.000Z",
      "direction": "incoming",
      "status": "delivered"
    }
  ],
  "count": 1,
  "total": 42
}
```

Note: The `content` field contains the **decrypted** plaintext. Encrypted payloads are never returned by this endpoint.

#### `POST /messages/receive`

Webhook endpoint for receiving messages from other fleets. This is the only externally-facing write endpoint.

**Request:** A full message envelope (see [Message Format](#3-message-format)).

```json
{
  "id": "01JMAX...",
  "from": "base64-ed25519-pubkey-of-sender",
  "to": "base64-ed25519-pubkey-of-this-fleet",
  "type": "text",
  "payload": "YWdlLWVuY3J5cHRpb24u...",
  "signature": "base64-ed25519-signature",
  "timestamp": "2026-02-18T22:00:00.000Z",
  "nonce": "base64-random-24-bytes"
}
```

**Processing steps:**

1. Verify `to` matches this fleet's public key → `400` if not
2. Verify `signature` against `from` public key → `401` if invalid
3. Check for replay (nonce + timestamp dedup) → `409` if duplicate
4. Check sender trust level:
   - `blocked` → silently drop, return `200`
   - `trusted` → decrypt, store in messages, push to inbox
   - `pending` / `unknown` / not in contacts → store in quarantine
5. Return `200` with ack

**Response:**
```json
{
  "received": true,
  "id": "01JMAX..."
}
```

#### `GET /stream`

SSE (Server-Sent Events) stream of new messages and inbox items.

**Event types:**
```
event: message
data: {"id":"01JMAX...","from":"...","type":"text","content":"...","timestamp":"..."}

event: inbox
data: {"id":"01JMAX...","source":"discord","channel":"discord","content":"..."}

event: quarantine
data: {"id":"01JMAX...","from_key":"...","received_at":"..."}

event: migration
data: {"contact":"...","old_endpoint":"...","new_endpoint":"..."}

event: ping
data: {"timestamp":"2026-02-18T22:00:00.000Z"}
```

The `ping` event is sent every 30 seconds to keep the connection alive.

---

### Contacts

#### `GET /contacts`

List all contacts.

**Query parameters:**
| Param         | Type   | Description |
|---------------|--------|-------------|
| `trust_level` | string | Filter by trust level |
| `search`      | string | Search display name |

**Response:**
```json
{
  "contacts": [
    {
      "id": "01JMAX...",
      "public_key": "base64-ed25519-pubkey",
      "display_name": "fleet-beta",
      "endpoint": "https://fleet-beta.example.com:3847",
      "trust_level": "trusted",
      "added_at": "2026-02-18T22:00:00.000Z",
      "last_seen": "2026-02-18T22:30:00.000Z"
    }
  ],
  "count": 1
}
```

#### `POST /contacts/add`

Add a new contact.

**Request:**
```json
{
  "public_key": "base64-ed25519-pubkey",
  "endpoint": "https://fleet-beta.example.com:3847",
  "display_name": "fleet-beta",
  "trust_level": "pending"
}
```

**Response:** `201 Created` with the contact record.

#### `POST /contacts/trust`

Change a contact's trust level.

**Request:**
```json
{
  "public_key": "base64-ed25519-pubkey",
  "trust_level": "trusted"
}
```

**Response:**
```json
{
  "public_key": "base64-ed25519-pubkey",
  "display_name": "fleet-beta",
  "old_trust_level": "pending",
  "new_trust_level": "trusted"
}
```

#### `POST /contacts/generate-add-link`

Generate a single-use friend-add link.

**Request:**
```json
{
  "expires_in_hours": 24
}
```

**Response:**
```json
{
  "url": "https://fleet-alpha.example.com:3847/contacts/add-link?pubkey=...&endpoint=...&name=fleet-alpha&token=...",
  "token": "one-time-random-token",
  "expires_at": "2026-02-19T22:00:00.000Z"
}
```

#### `GET /contacts/add-link` (Public)

Accept a friend-add link. Returns the fleet's identity for the visiting fleet to consume.

**Query parameters:** `pubkey`, `endpoint`, `name`, `token`

**Response:**
```json
{
  "public_key": "base64-ed25519-pubkey",
  "endpoint": "https://fleet-alpha.example.com:3847",
  "display_name": "fleet-alpha",
  "age_public_key": "age1..."
}
```

The visiting fleet's software should automatically call `POST /contacts/add` on its own instance with this information.

---

### Quarantine

#### `GET /quarantine`

List quarantined messages.

**Query parameters:**
| Param    | Type   | Description |
|----------|--------|-------------|
| `status` | string | `pending`, `approved`, `rejected` (default: `pending`) |
| `from`   | string | Filter by sender pubkey |
| `limit`  | number | Max results (default: 50) |

**Response:**
```json
{
  "items": [
    {
      "id": "01JMAX...",
      "message_id": "01JMAX...",
      "from_key": "base64-ed25519-pubkey",
      "from_name": null,
      "received_at": "2026-02-18T22:00:00.000Z",
      "type": "text",
      "status": "pending"
    }
  ],
  "count": 1
}
```

Note: Message content is NOT included in the list response (it's still encrypted).

#### `POST /quarantine/:id/approve`

Approve a quarantined message: decrypt it, move to inbox, optionally set sender trust.

**Request:**
```json
{
  "set_trust": "trusted"
}
```

**Response:**
```json
{
  "approved": true,
  "message_id": "01JMAX...",
  "inbox_id": "01JMAX...",
  "sender_trust_updated": true
}
```

#### `POST /quarantine/:id/reject`

Reject a quarantined message.

**Request:**
```json
{
  "block_sender": false
}
```

**Response:**
```json
{
  "rejected": true,
  "message_id": "01JMAX...",
  "sender_blocked": false
}
```

---

### Inbox

#### `GET /inbox`

List fleet inbox items.

**Query parameters:**
| Param     | Type    | Description |
|-----------|---------|-------------|
| `channel` | string  | Filter by channel (`direct`, `discord`, `email`, etc.) |
| `read`    | boolean | Filter by read status |
| `archived`| boolean | Filter by archived status (default: `false`) |
| `since`   | string  | ISO 8601 timestamp |
| `limit`   | number  | Max results (default: 50) |

**Response:**
```json
{
  "items": [...],
  "count": 10,
  "unread": 3
}
```

#### `GET /inbox/unread-count`

**Response:**
```json
{
  "unread": 3,
  "by_channel": {
    "direct": 1,
    "discord": 2,
    "email": 0
  }
}
```

#### `POST /inbox/:id/read`

Mark an inbox item as read.

#### `POST /inbox/:id/archive`

Archive an inbox item.

---

### Watchers

#### `GET /watchers`

**Response:**
```json
{
  "watchers": [
    {
      "name": "discord",
      "enabled": true,
      "running": true,
      "last_poll": "2026-02-18T22:00:00.000Z",
      "messages_ingested": 142,
      "error": null
    }
  ]
}
```

#### `POST /watchers/:name/enable`
#### `POST /watchers/:name/disable`

Enable or disable a watcher at runtime.

---

## 10. SQLite Schema

Fleet-chat uses a single SQLite database file (`fleet-chat.db`).

```sql
-- Identity (singleton)
CREATE TABLE identity (
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
CREATE TABLE contacts (
  id TEXT PRIMARY KEY,                    -- ULID
  public_key BLOB NOT NULL UNIQUE,       -- Ed25519 public key
  display_name TEXT,
  endpoint TEXT NOT NULL,
  trust_level INTEGER NOT NULL DEFAULT 0, -- 0=unknown, 1=pending, 2=trusted, 3=blocked
  age_public_key TEXT,                    -- age X25519 public key
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT,
  notes TEXT
);

CREATE INDEX idx_contacts_trust ON contacts(trust_level);
CREATE INDEX idx_contacts_pubkey ON contacts(public_key);

-- Messages (decrypted, stored after successful receive/send)
CREATE TABLE messages (
  id TEXT PRIMARY KEY,                    -- ULID
  from_key BLOB NOT NULL,                -- sender Ed25519 pubkey
  to_key BLOB NOT NULL,                  -- recipient Ed25519 pubkey
  type TEXT NOT NULL,                     -- text, endpoint_migration, etc.
  content TEXT NOT NULL,                  -- decrypted plaintext
  metadata TEXT,                          -- JSON metadata
  direction TEXT NOT NULL,                -- 'incoming' or 'outgoing'
  status TEXT NOT NULL DEFAULT 'delivered', -- delivered, queued, failed
  timestamp TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_messages_from ON messages(from_key);
CREATE INDEX idx_messages_to ON messages(to_key);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);
CREATE INDEX idx_messages_type ON messages(type);

-- Outbound queue (messages waiting for retry)
CREATE TABLE outbound_queue (
  id TEXT PRIMARY KEY,                    -- ULID
  message_id TEXT NOT NULL,
  to_key BLOB NOT NULL,
  to_endpoint TEXT NOT NULL,
  envelope TEXT NOT NULL,                 -- full JSON envelope
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_retry_at TEXT NOT NULL,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_outbound_next_retry ON outbound_queue(next_retry_at);

-- Quarantine
CREATE TABLE quarantine (
  id TEXT PRIMARY KEY,                    -- ULID
  message_id TEXT NOT NULL,              -- original message ID
  from_key BLOB NOT NULL,
  envelope TEXT NOT NULL,                 -- full JSON envelope (still encrypted)
  type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, rejected
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT,
  reviewed_by TEXT
);

CREATE INDEX idx_quarantine_status ON quarantine(status);
CREATE INDEX idx_quarantine_from ON quarantine(from_key);

-- Fleet Inbox
CREATE TABLE inbox (
  id TEXT PRIMARY KEY,                    -- ULID
  source TEXT NOT NULL,                   -- fleet-chat, discord, email, etc.
  source_id TEXT,                         -- source-specific identifier
  source_name TEXT,                       -- human-readable source name
  channel TEXT NOT NULL,                  -- direct, discord, email, etc.
  content TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'text/plain',
  metadata TEXT,                          -- JSON
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  read INTEGER NOT NULL DEFAULT 0,
  archived INTEGER NOT NULL DEFAULT 0,
  original_message_id TEXT               -- reference to messages.id if from fleet-chat
);

CREATE INDEX idx_inbox_channel ON inbox(channel);
CREATE INDEX idx_inbox_read ON inbox(read);
CREATE INDEX idx_inbox_archived ON inbox(archived);
CREATE INDEX idx_inbox_received ON inbox(received_at);

-- Nonce dedup (replay protection)
CREATE TABLE seen_nonces (
  nonce TEXT PRIMARY KEY,
  from_key BLOB NOT NULL,
  seen_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Purge nonces older than 24 hours (run periodically)
-- DELETE FROM seen_nonces WHERE seen_at < datetime('now', '-24 hours');

-- Friend-add tokens
CREATE TABLE add_link_tokens (
  token TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  used_by_key BLOB
);

-- Watcher state
CREATE TABLE watcher_state (
  name TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  last_poll TEXT,
  last_cursor TEXT,                       -- service-specific cursor/offset
  messages_ingested INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Key rotation history
CREATE TABLE key_history (
  id TEXT PRIMARY KEY,
  public_key BLOB NOT NULL,
  private_key BLOB NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT,                        -- null = current key
  rotated_at TEXT
);
```

---

## 11. Security Considerations

### Threat Model

Fleet-chat assumes:
- The network is hostile (all traffic may be intercepted)
- Any fleet may be compromised (trust is explicit, not default)
- Endpoints are ephemeral (VMs can be recreated by anyone)

Fleet-chat does NOT protect against:
- Compromise of the local machine (if an attacker has access to the SQLite DB, they have the private key)
- Side-channel attacks on the encryption implementation
- Denial of service (rate limiting is recommended but not part of the core protocol)

### Encryption

- **Algorithm:** age encryption with X25519 recipients
- **Key derivation:** Ed25519 → X25519 conversion (RFC 8032 compliant)
- **Forward secrecy:** Not provided by default. Each message is encrypted to the recipient's long-term key. For forward secrecy, implement ephemeral key exchange (future extension).

### Signature Verification

- **All** incoming messages MUST have their signature verified before any processing
- Invalid signatures → `401 Unauthorized`, message dropped
- The `from` field in the envelope is the public key used for verification — it is self-authenticating

### Replay Protection

- The `nonce` field MUST be unique per message
- The receiver stores seen nonces for 24 hours
- Messages with duplicate `nonce` values → `409 Conflict`
- Messages with timestamps older than 24 hours → rejected
- Messages with timestamps more than 5 minutes in the future → rejected (clock skew tolerance)

### Rate Limiting

Recommended (not required by protocol):
- Incoming messages: 60/minute per sender
- API requests: 120/minute per IP
- SSE connections: 5 concurrent per IP

### Private Key Protection

- Private keys are stored in SQLite, which SHOULD be on an encrypted filesystem
- Private keys are NEVER included in API responses
- Private keys are NEVER logged
- Consider using SQLite encryption extension (SQLCipher) for at-rest encryption

### Trust Escalation Prevention

- Messages from non-trusted senders NEVER reach the agent
- Quarantine approval is a deliberate operator/agent action
- No mechanism exists for an external fleet to auto-promote itself to trusted
- The `key_exchange` message type does NOT imply trust — it merely provides cryptographic material

---

## 12. Deployment Guide

### Prerequisites

- Node.js >= 20.x
- npm or yarn

### Installation

```bash
git clone https://github.com/fleet-chat/fleet-chat.git
cd fleet-chat
npm install
```

### Configuration

Environment variables:

| Variable                | Required | Default | Description |
|-------------------------|----------|---------|-------------|
| `FLEET_CHAT_PORT`       | no       | `3847`  | HTTP server port |
| `FLEET_CHAT_HOST`       | no       | `0.0.0.0` | Bind address |
| `FLEET_CHAT_API_TOKEN`  | yes      | —       | Bearer token for API auth |
| `FLEET_CHAT_ENDPOINT`   | yes      | —       | This fleet's public URL (e.g., `https://my-fleet.example.com:3847`) |
| `FLEET_CHAT_DISPLAY_NAME` | no    | `unnamed-fleet` | Human-readable fleet name |
| `FLEET_CHAT_DB_PATH`    | no       | `./fleet-chat.db` | Path to SQLite database |
| `FLEET_CHAT_TLS_CERT`   | no       | —       | Path to TLS certificate |
| `FLEET_CHAT_TLS_KEY`    | no       | —       | Path to TLS private key |
| `DISCORD_BOT_TOKEN`     | no       | —       | Discord watcher bot token |
| `EMAIL_USERNAME`         | no       | —       | Email watcher IMAP username |
| `EMAIL_PASSWORD`         | no       | —       | Email watcher IMAP password |
| `TWITTER_API_KEY`        | no       | —       | Twitter watcher API key |
| `TWITTER_API_SECRET`     | no       | —       | Twitter watcher API secret |

### First Run

```bash
# Set required env vars
export FLEET_CHAT_API_TOKEN="$(openssl rand -hex 32)"
export FLEET_CHAT_ENDPOINT="https://my-fleet.example.com:3847"
export FLEET_CHAT_DISPLAY_NAME="fleet-alpha"

# Start
npm start
```

On first run, fleet-chat will:
1. Create the SQLite database
2. Generate an Ed25519 keypair
3. Derive the age X25519 keys
4. Start the HTTP server
5. Log the public key to stdout

### TLS

Fleet-chat SHOULD be deployed behind TLS. Options:

1. **Built-in TLS**: Set `FLEET_CHAT_TLS_CERT` and `FLEET_CHAT_TLS_KEY`
2. **Reverse proxy**: Use nginx, caddy, or similar with TLS termination
3. **Platform TLS**: If deployed on a platform that provides TLS (e.g., Vers VMs with HTTPS endpoints)

### Health Check

```bash
curl https://fleet.example.com:3847/identity
```

Returns the fleet's public identity. If this responds, the service is running.

### Systemd Service

```ini
[Unit]
Description=fleet-chat
After=network.target

[Service]
Type=simple
User=fleet
WorkingDirectory=/opt/fleet-chat
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=5
Environment=FLEET_CHAT_API_TOKEN=your-token-here
Environment=FLEET_CHAT_ENDPOINT=https://fleet.example.com:3847

[Install]
WantedBy=multi-user.target
```

---

## 13. Interoperability Notes

### Compatibility with Existing Implementations

Fleet-chat is designed to interoperate with existing fleet messaging implementations. This section documents known compatibility considerations.

### Envelope Field Names

The canonical envelope uses `from` and `to` fields (Ed25519 public keys). Some implementations may use alternative field names:

| This Spec | Alternative | Handling |
|-----------|-------------|----------|
| `from`    | `sender`    | Accept both on receive; always send `from` |
| `to`      | `recipient` | Accept both on receive; always send `to` |

Fleet-chat SHOULD accept messages with either field name on the `/messages/receive` endpoint.

### Encrypted Payload Detection

Some fleet implementations send messages with `type: "text"` where the payload is age-encrypted (base64), rather than using a distinct content type. Fleet-chat SHOULD detect encrypted payloads by:

1. Checking if the payload starts with the age header: `YWdlLWVuY3J5cHRpb24` (base64 of "age-encryption")
2. If so, attempt decryption regardless of the declared type
3. If decryption fails, treat as plaintext (legacy compatibility)

### Message ID Formats

This spec uses ULIDs. Other implementations may use UUIDs or other ID formats. Fleet-chat MUST accept any string as a message ID — do not validate the format.

### Timestamp Tolerance

Different fleets may have clock drift. Fleet-chat SHOULD accept timestamps within a ±5 minute window from the current time. For older messages (e.g., queued during an outage), extend tolerance to 24 hours but flag them as potentially replayed.

### Missing Fields

If an incoming message is missing optional fields (`nonce`, `metadata`), fleet-chat SHOULD process it gracefully:

- Missing `nonce`: Generate a synthetic nonce from `hash(id + timestamp)` for dedup purposes. Log a warning.
- Missing `metadata`: Default to `{}`

### Plaintext Fallback

Some fleets may not implement encryption. Fleet-chat SHOULD handle plaintext payloads:

1. If the payload is valid JSON (not base64-encoded ciphertext), treat as plaintext
2. Store with a `plaintext_warning: true` flag
3. Display a warning to the operator that the message was not encrypted
4. Still verify the signature if present

### Version Negotiation

The `/identity` endpoint includes a `version` field and `capabilities` array. Fleets SHOULD check capabilities before sending messages that require specific features. If a fleet does not advertise `endpoint_migration` in capabilities, fall back to manual endpoint updates.

---

## Appendix A: Wire Protocol Examples

### Example: Sending a Text Message

**fleet-alpha sends "Hello" to fleet-beta:**

1. fleet-alpha constructs the plaintext payload:
```json
{"type":"text","content":"Hello from fleet-alpha!","metadata":{}}
```

2. fleet-alpha encrypts the payload to fleet-beta's age public key:
```
age-encryption.org/v1
-> X25519 <fleet-beta-age-pubkey>
<encrypted-payload-bytes>
```

3. fleet-alpha constructs the envelope:
```json
{
  "id": "01JMAXYZ1234567890ABCDEF",
  "from": "<fleet-alpha-ed25519-pubkey-base64>",
  "to": "<fleet-beta-ed25519-pubkey-base64>",
  "type": "text",
  "payload": "<base64-of-age-ciphertext>",
  "signature": "<base64-of-ed25519-sign(payload+nonce+timestamp)>",
  "timestamp": "2026-02-18T22:00:00.000Z",
  "nonce": "<base64-of-24-random-bytes>"
}
```

4. fleet-alpha sends `POST https://fleet-beta.example.com:3847/messages/receive` with the envelope as the body.

5. fleet-beta verifies signature, decrypts, stores, returns `{"received": true}`.

### Example: Endpoint Migration

**fleet-alpha moves from old-vm to new-vm:**

1. fleet-alpha starts on new-vm
2. Detects endpoint change
3. For each trusted contact, sends an `endpoint_migration` message
4. Contacts verify signature, update their contact records

### Example: Friend Add Flow

1. fleet-alpha generates a link: `GET /contacts/generate-add-link`
2. fleet-alpha shares the link with fleet-beta out-of-band
3. fleet-beta's operator visits the link or fleet-beta's software fetches it
4. fleet-beta extracts pubkey + endpoint from the link
5. fleet-beta calls its own `POST /contacts/add` with fleet-alpha's info
6. fleet-beta sends a `key_exchange` message to fleet-alpha
7. fleet-alpha receives it (quarantined if fleet-beta is unknown)
8. fleet-alpha's operator approves and promotes fleet-beta to trusted

---

## Appendix B: Error Codes

| HTTP Status | Code                    | Description |
|-------------|-------------------------|-------------|
| 400         | `INVALID_ENVELOPE`      | Malformed message envelope |
| 400         | `WRONG_RECIPIENT`       | `to` field doesn't match this fleet |
| 401         | `INVALID_SIGNATURE`     | Ed25519 signature verification failed |
| 401         | `UNAUTHORIZED`          | Missing or invalid bearer token |
| 404         | `CONTACT_NOT_FOUND`     | Contact pubkey not found |
| 404         | `MESSAGE_NOT_FOUND`     | Message ID not found |
| 409         | `DUPLICATE_NONCE`       | Replay attack detected (nonce reuse) |
| 413         | `PAYLOAD_TOO_LARGE`     | Envelope exceeds 64 KiB |
| 429         | `RATE_LIMITED`          | Too many requests |
| 500         | `ENCRYPTION_FAILED`     | Failed to encrypt payload |
| 500         | `DECRYPTION_FAILED`     | Failed to decrypt payload |
| 503         | `PEER_UNREACHABLE`      | Could not connect to recipient endpoint |

---

## Appendix C: Future Extensions

The following features are out of scope for v2 but may be added in future versions:

1. **Group messaging** — Multi-party encrypted channels (using MLS or similar)
2. **Forward secrecy** — Ephemeral key exchange per session (Double Ratchet)
3. **File transfer** — Encrypted file sharing with resumable uploads
4. **Fleet directory** — Opt-in public directory of fleet identities
5. **Message reactions** — Lightweight acknowledgment beyond `ack`
6. **Capability negotiation** — Formal capability discovery and version negotiation
7. **Onion routing** — Route messages through intermediary fleets for anonymity
8. **Offline delivery** — Store-and-forward through relay nodes when recipient is offline


---
