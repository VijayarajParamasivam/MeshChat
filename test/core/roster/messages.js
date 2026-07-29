'use strict';

/**
 * Sending, acknowledging, and — the part that was a bug — resending.
 *
 * A message written into a circuit that then died used to be marked `sent` and
 * never looked at again. It is now still owed a retry, and the receiving side
 * recognises a copy it already holds and re-acknowledges it instead of filing a
 * duplicate. Those two behaviours only work together, so they are tested
 * against each other here.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const store = require('../../../src/core/store');
const { Messenger } = require('../../../src/core/roster/messages');
const { suite } = require('../../../scripts/harness');

const { check, run } = suite();
const PEER = 'TOR-PEER-PEER-PEER';
const FRIEND = { id: PEER, name: 'bob' };

/** A link that records what it was asked to send, and can refuse. */
function fakeLink({ accepts = true } = {}) {
  const sent = [];
  return {
    sent,
    send(frame) {
      if (!accepts) return false;
      sent.push(frame);
      return true;
    },
  };
}

run(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-messenger-'));
  store.init(dir);
  store.resetCache();

  const events = [];
  const links = new Map();
  const messenger = new Messenger({
    store,
    links,
    emit: (event, payload) => events.push({ event, payload }),
    log: () => {},
  });

  // --- composing with nobody there -----------------------------------------

  const offline = messenger.compose(PEER, 'while you were out');
  check('a message with no link stays queued', offline.state === 'queued');
  check('and is stored anyway', store.recentMessages(PEER).length === 1);

  // --- composing with a live link ------------------------------------------

  const link = fakeLink();
  links.set(PEER, link);

  const sent = messenger.compose(PEER, 'hello');
  check('a message with a link is sent', sent.state === 'sent');
  check('and went out as a msg frame', link.sent.at(-1).t === 'msg');
  check('carrying the body', link.sent.at(-1).body === 'hello');
  check('and no local bookkeeping', !('mine' in link.sent.at(-1)));

  // --- a link that refuses -------------------------------------------------

  links.set(PEER, fakeLink({ accepts: false }));
  const refused = messenger.compose(PEER, 'nope');
  check('a refused write leaves it queued', refused.state === 'queued');
  links.set(PEER, link);

  // --- the outbox ----------------------------------------------------------

  const before = link.sent.length;
  messenger.flushOutbox(PEER);
  check('flushing resends everything unacknowledged', link.sent.length > before);
  check(
    'including one already marked sent',
    link.sent.slice(before).some((f) => f.body === 'hello')
  );

  messenger.acknowledge(PEER, { id: sent.id });
  check('an ack marks it delivered', store.recentMessages(PEER).find((m) => m.id === sent.id).state === 'delivered');
  check('and announces it', events.some((e) => e.event === 'delivered'));

  const afterAck = link.sent.length;
  messenger.flushOutbox(PEER);
  check(
    'a delivered message is not resent',
    !link.sent.slice(afterAck).some((f) => f.id === sent.id)
  );

  // --- receiving -----------------------------------------------------------

  messenger.receive(PEER, FRIEND, { id: 'theirs-1', ts: 111, body: 'hi back' });
  check('a received message is announced', events.some((e) => e.event === 'message'));
  check('and acknowledged', link.sent.at(-1).t === 'ack' && link.sent.at(-1).id === 'theirs-1');
  check('and filed', store.hasMessage(PEER, 'theirs-1'));

  const filedBefore = store.recentMessages(PEER, 0).length;
  const eventsBefore = events.filter((e) => e.event === 'message').length;

  messenger.receive(PEER, FRIEND, { id: 'theirs-1', ts: 111, body: 'hi back' });
  check('a duplicate is not filed twice', store.recentMessages(PEER, 0).length === filedBefore);
  check(
    'nor shown twice',
    events.filter((e) => e.event === 'message').length === eventsBefore
  );
  check('but it is acknowledged again', link.sent.at(-1).id === 'theirs-1');

  // --- an ack that collides with their id -----------------------------------
  //
  // IDs are chosen by whoever composed the message, so a peer could name one of
  // ours. An ack must only ever match our own half of the ID space.

  messenger.acknowledge(PEER, { id: 'theirs-1' });
  check(
    'an ack cannot touch their own message',
    store.recentMessages(PEER, 0).find((m) => m.id === 'theirs-1' && !m.mine).state === 'received'
  );

  // --- history --------------------------------------------------------------

  check('history is readable', messenger.history(PEER, 5).length > 0);
  check('history can be limited', messenger.history(PEER, 1).length === 1);

  fs.rmSync(dir, { recursive: true, force: true });
});
