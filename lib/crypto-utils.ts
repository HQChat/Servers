import * as crypto from "crypto";

/**
 * Pure, dependency-free crypto helpers shared by the DB and Stripe layers.
 * Kept separate so they can be unit-tested without importing the database layer.
 */

/**
 * Conversation topic identifier: SHA-256 over the two CLIENT IDS sorted, so the
 * hash is identical regardless of argument order.
 *
 * The parameters were public keys until the identifier change; every caller
 * passes ids now (`grantFriendTopic`, the friendships row, `MQTTTopics` on the
 * client). Since an id is itself `sha256(hex(pk))`, the result is a hash of a
 * hash — which changes nothing about the value's properties but does change what
 * you must pass in. Mixing the two forms silently yields a topic that no ACL
 * grants and no peer subscribes to.
 *
 * It is NOT blind, and the old comment saying so outlived the design: the
 * `friendships` row stores `id_lo` and `id_hi` beside this hash, so the server
 * does know who is friends with whom. `getHashMembers` depends on exactly that.
 * The site says as much in plain words rather than claiming otherwise.
 */
export function friendshipHash(idA: string, idB: string): string {
  const sorted = [idA, idB].sort().join("");
  return crypto.createHash("sha256").update(sorted).digest("hex");
}
