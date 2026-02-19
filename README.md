# fleet-chat

Standalone fleet-to-fleet messaging protocol and service.

Secure, encrypted, identity-based messaging between autonomous agent fleets.

## Overview

Fleet-chat enables autonomous agent fleets to communicate with each other using:
- **Ed25519 keypairs** for identity (not URLs — identity survives VM migration)
- **age encryption** for message confidentiality
- **Ed25519 signatures** for sender authentication
- **Endpoint migration** protocol for when fleets move between VMs
- **Asymmetric trust** model with quarantine for unknown senders

## Files

- `SPEC.md` — Complete protocol specification (44K chars)
- `SEED.md` — Seed file for fleet-chat (TOML frontmatter + markdown)

## Status

Specification complete. Implementation in progress.
