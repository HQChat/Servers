/**
 * The MQTT topic vocabulary, server side. The Swift counterpart is
 * apps/apple/DissQus/Services/MQTTTopics.swift; the broker's view of it is
 * infra/deploy/emqx/acl.conf.
 *
 * Conversation and handshake topics are CAPABILITIES: `cv/{convo_id}` and
 * `hs/{handshake_id}` name 64-hex random ids minted per friendship
 * (migrations/009_friendship_topics.sql) and handed only to its two members. The
 * broker allows `cv/+` and `hs/+` to any authenticated client and refuses
 * wildcard subscriptions, so knowing the id is the permission.
 *
 * The per-user topics stay addressed by client id. The static ACL makes presence
 * owner-publish-only and inbox/graph owner-subscribe-only; anyone who knows an id
 * may read its presence and publish to its inbox — a deliberate trade, see
 * docs/architecture/emqx-acl.md.
 */

/** A topic id as minted by 009: 64 lowercase hex characters. */
export const TOPIC_ID = /^[0-9a-f]{64}$/;

export function conversationTopic(convoId: string): string {
  return `cv/${convoId}`;
}

export function handshakeTopic(handshakeId: string): string {
  return `hs/${handshakeId}`;
}

export function presenceTopic(id: string): string {
  return `u/${id}/presence`;
}

export function inboxTopic(id: string): string {
  return `u/${id}/inbox`;
}

/** Where the server says "your friend graph moved". Owner-subscribe-only; the
 *  server publishes through the admin API, which the authorizer never sees. */
export function graphTopic(id: string): string {
  return `u/${id}/graph`;
}
