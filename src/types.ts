// Trust levels
export const TrustLevel = {
  UNKNOWN: 0,
  PENDING: 1,
  TRUSTED: 2,
  BLOCKED: 3,
} as const;

export type TrustLevelValue = (typeof TrustLevel)[keyof typeof TrustLevel];

export const TrustLevelName: Record<TrustLevelValue, string> = {
  0: "unknown",
  1: "pending",
  2: "trusted",
  3: "blocked",
};

export const TrustLevelFromName: Record<string, TrustLevelValue> = {
  unknown: 0,
  pending: 1,
  trusted: 2,
  blocked: 3,
};

// Message types
export type MessageType =
  | "text"
  | "endpoint_migration"
  | "key_exchange"
  | "key_rotation"
  | "ping"
  | "ack";

// Wire format
export interface MessageEnvelope {
  id: string;
  from: string; // Ed25519 public key, base64
  to: string; // Ed25519 public key, base64
  type: MessageType;
  payload: string; // age-encrypted, base64
  signature: string; // Ed25519 signature, base64
  timestamp: string; // ISO 8601
  nonce: string; // random bytes, base64
  // Sender identity metadata (informational, not authenticated)
  sender_name?: string; // display name of sender
  sender_endpoint?: string; // sender's endpoint URL
  sender_age_key?: string; // sender's age public key (for reply encryption)
  // Social attestations — URLs where sender's public key can be verified
  attestations?: string[];
}

// Decrypted payload
export interface MessagePayload {
  type: MessageType;
  content: string;
  metadata?: Record<string, unknown>;
}

// Stored message
export interface StoredMessage {
  id: string;
  from_key: string;
  to_key: string;
  type: MessageType;
  content: string;
  metadata: string | null;
  direction: "incoming" | "outgoing";
  status: "delivered" | "queued" | "failed";
  timestamp: string;
  created_at: string;
}

// Contact — the joined view callers see
export interface Contact {
  id: string;
  public_key: string; // base64 — primary key (from contact_keys)
  display_name: string | null;
  endpoint: string;
  trust_level: TrustLevelValue;
  age_public_key: string | null;
  added_at: string;
  last_seen: string | null;
  notes: string | null;
}

// Contact key — one contact can have many keys
export interface ContactKey {
  id: string;
  contact_id: string;
  public_key: string; // base64 ed25519
  key_type: string; // 'ed25519'
  age_public_key: string | null; // optional explicit age key
  added_at: string;
  last_used: string | null;
}

// Social attestation — URL where a contact's public key can be verified
export interface Attestation {
  id: string;
  contact_id: string;
  url: string;
  status: "pending" | "verified" | "rejected";
  verified_at: string | null;
  verified_by: string | null; // 'operator' or 'agent'
  notes: string | null;
  added_at: string;
}

// Quarantine item
export interface QuarantineItem {
  id: string;
  message_id: string;
  from_key: string;
  envelope: string; // JSON
  type: string;
  status: "pending" | "approved" | "rejected";
  received_at: string;
  reviewed_at: string | null;
  reviewed_by: string | null;
}

// Inbox item
export interface InboxItem {
  id: string;
  source: string;
  source_id: string | null;
  source_name: string | null;
  channel: string;
  content: string;
  content_type: string;
  metadata: string | null;
  received_at: string;
  read: number;
  archived: number;
  original_message_id: string | null;
}

// Identity
export interface Identity {
  public_key: Buffer;
  private_key: Buffer;
  age_public_key: string;
  age_private_key: string;
  display_name: string;
  endpoint: string;
  created_at: string;
}

// Add link token
export interface AddLinkToken {
  token: string;
  created_at: string;
  expires_at: string;
  used: number;
  used_by_key: string | null;
}
