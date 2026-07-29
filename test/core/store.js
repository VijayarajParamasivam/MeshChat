'use strict';

/**
 * Everything the app knows lives on this disk and nowhere else.
 *
 * Two rules here were bugs first. Message IDs are chosen by whoever composed the
 * message, so the two directions share an ID space neither side controls both
 * halves of — every lookup is scoped by `mine` or a peer could mark our messages
 * delivered. And the in-memory conversation cache has to be droppable, or
 * restoring a backup writes the previous identity's history back out under the
 * new one.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const store = require('../../src/core/store');
const { suite } = require('../../scripts/harness');

const { check, run } = suite();
const PEER = 'TOR-TEST-TEST-TEST';

run(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-store-'));
  store.init(dir);

  // --- the outbox ---------------------------------------------------------

  store.appendMessage(PEER, { id: 'a', ts: 1, body: 'queued', mine: true, state: 'queued' });
  store.appendMessage(PEER, { id: 'b', ts: 2, body: 'sent', mine: true, state: 'sent' });
  store.appendMessage(PEER, { id: 'd', ts: 3, body: 'done', mine: true, state: 'delivered' });
  store.appendMessage(PEER, { id: 'r', ts: 4, body: 'theirs', mine: false, state: 'received' });

  const pending = store.undelivered(PEER).map((m) => m.id);
  check('a queued message is retried', pending.includes('a'));
  check('an unacknowledged sent message is retried too', pending.includes('b'));
  check('a delivered message is not resent', !pending.includes('d'));
  check('their message is never in our outbox', !pending.includes('r'));

  // --- direction scoping --------------------------------------------------

  store.appendMessage(PEER, { id: 'x', ts: 5, body: 'ours', mine: true, state: 'sent' });
  check('an inbound id does not collide with ours', store.hasMessage(PEER, 'x') === false);

  store.appendMessage(PEER, { id: 'x', ts: 6, body: 'theirs', mine: false, state: 'received' });
  check('a genuine resend is recognised', store.hasMessage(PEER, 'x') === true);

  const acked = store.updateMessage(PEER, 'x', { state: 'delivered' }, true);
  check('an ack matches our copy, not theirs', acked && acked.body === 'ours');

  const inbound = store.updateMessage(PEER, 'x', { state: 'seen' }, false);
  check('and their copy is reachable on its own side', inbound && inbound.body === 'theirs');

  check('an unknown id patches nothing', store.updateMessage(PEER, 'nope', {}, true) === null);

  // --- history ------------------------------------------------------------

  check('history comes back', store.recentMessages(PEER).length > 0);
  check('history can be limited', store.recentMessages(PEER, 2).length === 2);

  // --- friends and settings -----------------------------------------------

  store.writeFriends([{ id: 'TOR-A', name: 'a' }]);
  check('friends round trip', store.readFriends()[0].id === 'TOR-A');
  check('a missing friend file is an empty list', Array.isArray(store.readFriends()));

  store.writeSettings({ onionKey: 'k' });
  check('settings round trip', store.readSettings().onionKey === 'k');
  store.writeSettings({ other: 1 });
  check('settings merge rather than replace', store.readSettings().onionKey === 'k');

  // --- the cache ----------------------------------------------------------

  store.flush();
  check('flushing writes the conversation out', fs.existsSync(path.join(dir, 'messages', `${PEER}.json`)));

  store.resetCache();
  fs.rmSync(path.join(dir, 'messages'), { recursive: true, force: true });
  fs.mkdirSync(path.join(dir, 'messages'), { recursive: true });
  check('resetCache drops the in-memory history', store.recentMessages(PEER).length === 0);

  fs.rmSync(dir, { recursive: true, force: true });
});
