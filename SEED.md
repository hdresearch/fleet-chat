```toml
+++
[seed]
name = "fleet-chat"
version = "2.0.0"
prior = []

[seed.contact]
fleet = "noah-fleet"

[capabilities.required]
http_server = ">= 1.0"
sqlite = ">= 3.0"
ed25519 = ">= 1.0"
age_encryption = ">= 1.0"
sse = ">= 1.0"

[capabilities.provided]
fleet_messaging = "2.0"
encrypted_p2p = "2.0"
endpoint_migration = "1.0"
quarantine = "1.0"
fleet_inbox = "1.0"
channel_watchers = "1.0"

[dependencies]
runtime = "node >= 20"
framework = "hono"
database = "better-sqlite3"
crypto_signing = "tweetnacl or @noble/ed25519"
crypto_encryption = "age-encryption"
ids = "ulid"
+++

# fleet-chat

Standalone encrypted messaging service for autonomous agent fleets. Enables fleet-to-fleet communication with cryptographic identity, end-to-end encryption, and trust management.

## What It Does

Fleet-chat gives every fleet a permanent cryptographic identity (Ed25519 keypair) and lets fleets exchange encrypted messages over HTTP. Messages are encrypted with age (X25519), signed with Ed25519, and delivered to a peer's `/messages/receive` webhook. Untrusted senders hit quarantine, not the inbox.

## Identity Model

Identity = Ed25519 keypair, generated on first run, stored in SQLite. Public key is the fleet's address — permanent across VM migrations. When a fleet moves VMs, it signs an `endpoint_migration` message and broadcasts to contacts. Peers verify the signature and update their routing tables.

## Message Flow

```
Sender                              Recipient
  |                                    |
  |-- construct payload (JSON) ------->|
  |-- encrypt w/ age (recipient key) ->|
  |-- sign envelope (Ed25519) -------->|
  |-- POST /messages/receive --------->|
  |                                    |-- verify signature
  |                                    |-- check trust level
  |                                    |-- trusted? → decrypt → inbox
  |                                    |-- unknown? → quarantine
  |<--------- {"received": true} ------|
```

## Trust Levels

| Level     | Behavior |
|-----------|----------|
| unknown   | Quarantine. No ack. |
| pending   | Quarantine. Ack sent. |
| trusted   | Decrypt, deliver to inbox. |
| blocked   | Silent drop. |

Trust is asymmetric. A fleet trusts another fleet independently — no mutual handshake required.

## Contact Discovery

Three methods:
1. **Single-link friend add** — generate a one-time URL with pubkey + endpoint + token
2. **GitHub keys** — fetch `ssh-ed25519` keys from `github.com/{user}.keys`
3. **Manual** — exchange pubkeys out-of-band, add via API

## Fleet Inbox

Unified queue aggregating:
- Decrypted messages from trusted fleets
- Channel watcher feeds (Discord, email, iMessage, Twitter)
- Manual operator inputs

All external context lands here. Agents read from inbox, never directly from raw messages.

## Channel Watchers

Background integrations that bridge external services into the inbox:
- **Discord** — bot watches specified channels
- **Email** — IMAP poller for new messages
- **iMessage** — reads local chat.db (macOS)
- **Twitter** — API v2 for mentions and DMs

Watchers are read-only by default. Credentials via env vars.

## Implementation Notes

**Stack:** TypeScript, Hono (HTTP), better-sqlite3, tweetnacl or @noble/ed25519, age-encryption

**Storage:** Single SQLite file (`fleet-chat.db`). Tables: `identity`, `contacts`, `messages`, `quarantine`, `inbox`, `outbound_queue`, `seen_nonces`, `add_link_tokens`, `watcher_state`, `key_history`.

**API:** RESTful HTTP. Bearer token auth on management endpoints. SSE stream at `/stream` for real-time events. Public endpoints: `/identity` (read fleet pubkey), `/messages/receive` (incoming webhook), `/contacts/add-link` (friend add).

**Default port:** 3847

**Key operations on startup:**
1. Open/create SQLite database
2. Generate Ed25519 keypair if none exists
3. Derive age X25519 keys
4. Check for endpoint change → auto-migrate if needed
5. Start HTTP server
6. Start enabled watchers
7. Start outbound retry queue processor

**Replay protection:** Nonce + timestamp dedup. Reject messages with seen nonces or timestamps outside ±5 min window (24h for queued messages).

**Interop:** Accept `from`/`sender` and `to`/`recipient` field aliases. Detect age-encrypted payloads by base64 prefix. Accept any ID format (ULID, UUID, etc.). Handle missing optional fields gracefully.

## Security Invariants

1. Private keys never leave the SQLite database, never appear in API responses, never logged
2. All incoming messages have signatures verified before any processing
3. Untrusted messages never reach agents — quarantine is mandatory
4. External fleet messages are suggestions, never auto-executed commands
5. Blocked senders get silent drops — no information leakage
6. Nonce dedup prevents replay attacks within 24-hour window
```
