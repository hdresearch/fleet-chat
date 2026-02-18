import { getDb } from "./store.js";
import { getIdentity } from "./identity.js";
import { listContacts } from "./contacts.js";
import { sendMessage } from "./messages.js";
import { TrustLevel } from "./types.js";

/**
 * Migrate endpoint: notify all trusted contacts of the new endpoint.
 */
export async function migrateEndpoint(newEndpoint: string, reason: string = "vm_migration"): Promise<{
  migrated: boolean;
  oldEndpoint: string;
  newEndpoint: string;
  notificationsSent: number;
  notificationsFailed: number;
  failedContacts: string[];
}> {
  const identity = getIdentity();
  if (!identity) throw new Error("Identity not initialized");

  const oldEndpoint = identity.endpoint;

  // Update local endpoint
  const db = getDb();
  db.prepare("UPDATE identity SET endpoint = ? WHERE id = 1").run(newEndpoint);

  // Also update env for this process
  process.env.FLEET_CHAT_ENDPOINT = newEndpoint;

  // Get all trusted contacts
  const contacts = listContacts({ trustLevel: "trusted" });

  let sent = 0;
  let failed = 0;
  const failedContacts: string[] = [];

  for (const contact of contacts) {
    try {
      const result = await sendMessage({
        to: contact.public_key,
        type: "endpoint_migration",
        content: "Endpoint migration notification",
        metadata: {
          old_endpoint: oldEndpoint,
          new_endpoint: newEndpoint,
          reason,
          effective_at: new Date().toISOString(),
        },
      });

      if (result.delivered) {
        sent++;
      } else {
        failed++;
        failedContacts.push(contact.public_key);
      }
    } catch {
      failed++;
      failedContacts.push(contact.public_key);
    }
  }

  return {
    migrated: true,
    oldEndpoint,
    newEndpoint,
    notificationsSent: sent,
    notificationsFailed: failed,
    failedContacts,
  };
}
