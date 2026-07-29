'use strict';

/**
 * Conversations: composing, delivering, acknowledging and retrying.
 *
 * The delivery contract is the whole point of this file. A message is only
 * `delivered` when the peer says so. Anything else stays in the outbox and goes
 * again on the next link, because "sent" never meant more than "the socket
 * accepted the bytes" — and a circuit that dies a moment later takes those bytes
 * with it, silently. Retrying is safe because the receiving side recognises a
 * message it already has and simply re-acknowledges it.
 */

const Message = require('../../models/message');

class Messenger {
  /**
   * @param {object} deps
   *   store  persistence
   *   links  Map of peerId -> Link, shared with the engine
   *   emit   the engine's event emitter function
   *   log    the engine's log function
   */
  constructor({ store, links, emit, log }) {
    this.store = store;
    this.links = links;
    this.emit = emit;
    this.log = log;
  }

  _linkFor(peerId) {
    return this.links.get(peerId);
  }

  /** Write a message, hand it over if we can, and keep it until acknowledged. */
  compose(peerId, body) {
    const message = Message.compose(body);
    this.store.appendMessage(peerId, message);

    if (this._deliver(peerId, message)) message.state = Message.State.SENT;
    return message;
  }

  /**
   * Put one message on the wire and mark it sent if the socket took it.
   * @returns {boolean} whether anything was written
   */
  _deliver(peerId, message) {
    const link = this._linkFor(peerId);
    if (!link || !link.send(Message.toFrame(message))) return false;

    // "Sent" means the bytes were accepted for writing, nothing more. It stays
    // in the outbox until an ack arrives, so a circuit that dies in transit
    // costs a retry rather than the message.
    this.store.updateMessage(peerId, message.id, { state: Message.State.SENT }, true);
    return true;
  }

  _ack(peerId, id) {
    this._linkFor(peerId)?.send({ t: 'ack', id });
  }

  /** A message arrived from a friend. */
  receive(peerId, friend, frame) {
    const id = Message.idFrom(frame.id);

    // The sender retries anything it has no ack for, so the same message
    // legitimately arrives twice whenever an ack was the thing that got lost.
    // Re-acknowledge it — that is what they are waiting for — but do not file
    // or display it again.
    if (this.store.hasMessage(peerId, id)) return this._ack(peerId, id);

    const message = Message.fromFrame(frame, id);
    this.store.appendMessage(peerId, message);
    this._ack(peerId, message.id);
    this.emit('message', { peerId, name: friend.name, message });
  }

  /** A friend confirmed one of ours. */
  acknowledge(peerId, frame) {
    // Only ever our own outgoing messages: an ack names an ID the peer got
    // from us, so matching one of theirs would be a collision, not a receipt.
    const patch = { state: Message.State.DELIVERED };
    const updated = this.store.updateMessage(peerId, String(frame.id), patch, true);
    if (updated) this.emit('delivered', { peerId, id: updated.id });
  }

  /**
   * Hand over everything the peer has not acknowledged.
   *
   * This runs on every fresh link, so a message that went into a circuit which
   * then died is resent rather than lost. The peer discards a copy it already
   * has and re-acks it, which is what makes resending safe: the only cost of a
   * needless retry is one duplicate ack.
   */
  flushOutbox(peerId) {
    if (!this._linkFor(peerId)) return;

    const pending = this.store.undelivered(peerId);
    if (!pending.length) return;

    let sent = 0;
    for (const message of pending) {
      if (this._deliver(peerId, message)) sent += 1;
    }
    if (!sent) return;

    this.log(`resent ${sent} unacknowledged message(s)`);
    this.emit('history-changed', { peerId });
  }

  history(peerId, limit) {
    return this.store.recentMessages(peerId, limit);
  }
}

module.exports = { Messenger };
