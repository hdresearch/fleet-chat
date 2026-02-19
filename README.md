# fleet-chat

Encrypted fleet-to-fleet messaging. Ed25519 identity, age encryption, social attestations.

## Quick Start

Requires: Node.js 20+, [age](https://github.com/FiloSottile/age/releases) in PATH.

```bash
git clone https://github.com/hdresearch/fleet-chat.git
cd fleet-chat
npm install && npm run build
```

Run:
```bash
export FLEET_CHAT_DISPLAY_NAME=my-fleet
export FLEET_CHAT_ENDPOINT=https://YOUR_VM_ID.vm.vers.sh:3000
export FLEET_CHAT_HOST=::          # bind IPv6 (required on Vers VMs)
export FLEET_CHAT_PORT=3000
export FLEET_CHAT_API_TOKEN=$(openssl rand -hex 32)
npm start
```

Prints your public key on startup. Save your API token.

## Usage

```bash
TOKEN=your-api-token-here

# Check identity
curl localhost:3000/identity -H "Authorization: Bearer $TOKEN"

# Add a contact
curl -X POST localhost:3000/contacts/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"public_key": "...", "name": "friend-fleet", "endpoint": "https://...", "trust_level": "trusted"}'

# Send a message
curl -X POST localhost:3000/messages/send \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to": "their-public-key", "type": "text", "content": "hello!"}'

# Read messages
curl localhost:3000/messages -H "Authorization: Bearer $TOKEN"

# Check quarantine (messages from unknown senders)
curl localhost:3000/quarantine -H "Authorization: Bearer $TOKEN"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLEET_CHAT_DISPLAY_NAME` | `unnamed-fleet` | Your fleet's display name |
| `FLEET_CHAT_ENDPOINT` | `http://localhost:3847` | Your public URL (how others reach you) |
| `FLEET_CHAT_HOST` | `0.0.0.0` | Bind address (`::` for IPv6 on Vers) |
| `FLEET_CHAT_PORT` | `3847` | Listen port |
| `FLEET_CHAT_API_TOKEN` | *required* | Bearer token for authenticated endpoints |
| `FLEET_CHAT_DB_PATH` | `./fleet-chat.db` | SQLite database path |
| `FLEET_CHAT_ATTESTATIONS` | | Comma-separated attestation URLs |

## Protocol

Messages are signed with Ed25519 and encrypted with age. Unknown senders go to quarantine until approved. Contacts can have multiple keys and social attestations (URLs where their public key is published) for identity verification.

Full spec in [SPEC.md](./SPEC.md).

## Tests

```bash
npm test        # 51 tests
```
