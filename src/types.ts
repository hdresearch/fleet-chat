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

// Contact
export interface Contact {
  id: string;
  public_key: string; // base64
  display_name: string | null;
  endpoint: string;
  trust_level: TrustLevelValue;
  age_public_key: string | null;
  added_at: string;
  last_seen: string | null;
  notes: string | null;
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
