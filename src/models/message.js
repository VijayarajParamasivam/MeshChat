'use strict';

/**
 * A message: `{ id, ts, body, mine, state }`.
 *
 * `state` is the interesting field, because it encodes a delivery contract that
 * cost a bug to get right:
 *
 *   queued     composed here, nothing on the wire yet
 *   sent       the socket accepted the bytes — which is *not* delivery
 *   delivered  the peer said so, and only then
 *   received   it came from them
 *
 * Nothing but an ack may set `delivered`. A message written into a circuit that
 * dies a moment later is still `sent`, and `sent` is still owed a retry — that
 * distinction is what stops messages vanishing silently.
 *
 * IDs are chosen by whoever composed the message, so the two directions share an
 * ID space that neither side controls both halves of. Every lookup is scoped by
 * `mine` for that reason.
 */

const c = require('../core/crypto');

const MAX_BODY = 4000;
const MAX_ID = 64;

const State = {
  QUEUED: 'queued',
  SENT: 'sent',
  DELIVERED: 'delivered',
  RECEIVED: 'received',
};

function clampBody(value) {
  return String(value).slice(0, MAX_BODY);
}

/**
 * A peer's message ID, made safe to use as a key.
 *
 * Derived separately from the message itself because the receiving path needs
 * it before deciding whether this is a duplicate worth re-acknowledging.
 */
function idFrom(value) {
  return String(value || c.messageId()).slice(0, MAX_ID);
}

/** Something we are sending. */
function compose(body) {
  return {
    id: c.messageId(),
    ts: Date.now(),
    body: clampBody(body),
    mine: true,
    state: State.QUEUED,
  };
}

/** Something that arrived, with its ID already derived by the caller. */
function fromFrame(frame, id = idFrom(frame.id)) {
  return {
    id,
    ts: Number(frame.ts) || Date.now(),
    body: clampBody(frame.body || ''),
    mine: false,
    state: State.RECEIVED,
  };
}

/** The wire form. Only the fields a peer needs, never our local bookkeeping. */
function toFrame(message) {
  return { t: 'msg', id: message.id, ts: message.ts, body: message.body };
}

/** Is this one of ours that the peer has not confirmed? */
function isAwaitingAck(message) {
  return Boolean(message.mine) && message.state !== State.DELIVERED;
}

module.exports = {
  compose,
  fromFrame,
  toFrame,
  idFrom,
  isAwaitingAck,
  State,
  MAX_BODY,
  MAX_ID,
};
