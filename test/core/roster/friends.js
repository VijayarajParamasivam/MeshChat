'use strict';

/**
 * The friend list and how it reaches disk.
 *
 * The privacy claim this file has to keep is narrow and absolute: an address
 * that is not an onion cannot enter a friend record. A stored card from an
 * older build, or a hostile peer, may carry IPs — they are discarded on the way
 * in rather than merely sorted last, so there is never an address in the list
 * that could be dialled.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const store = require('../../../src/core/store');
const { FriendBook } = require('../../../src/core/roster/friends');
const { suite, ONION, OTHER_ONION } = require('../../../scripts/harness');

const { check, run } = suite();

run(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-friends-'));
  store.init(dir);
  store.resetCache();

  let changes = 0;
  const book = new FriendBook(store, () => { changes += 1; });

  const card = (over = {}) => ({
    id: 'TOR-A',
    name: 'bob',
    sigil: 'bb',
    sign: 's',
    box: 'b',
    ts: 5000,
    endpoints: [{ type: 'onion', host: ONION, port: 47777 }],
    ...over,
  });

  // --- adding --------------------------------------------------------------

  const { friend, isNew } = book.upsert(card());
  check('a first card creates a friend', isNew === true);
  check('the friend is retrievable', book.get('TOR-A') === friend);
  check('the book knows its size', book.size === 1);
  check('saving notifies', changes > 0);

  const again = book.upsert(card({ ts: 6000 }));
  check('a second card updates rather than duplicates', again.isNew === false);
  check('and the book has not grown', book.size === 1);

  // --- the privacy invariant -----------------------------------------------

  const target = { id: 'TOR-X', endpoints: [] };
  book.mergeEndpoints(target, [
    { type: 'ip6', host: '2409:40f4::1', port: 47777 },
    { type: 'lan', host: '192.168.1.5', port: 47777 },
    { type: 'wan', host: '49.37.1.2', port: 47777 },
    { type: 'onion', host: ONION, port: 47777 },
  ]);
  check('ip endpoints are dropped on merge', target.endpoints.length === 1);
  check('the onion survives', target.endpoints[0].host === ONION);

  book.upsert(card({ id: 'TOR-IP', endpoints: [{ type: 'wan', host: '49.37.1.2', port: 47777 }] }));
  check('a card full of ips yields no addresses', book.get('TOR-IP').endpoints.length === 0);

  // --- which card wins -----------------------------------------------------

  book.upsert(card({ name: 'imposter', ts: 1000, endpoints: [{ host: OTHER_ONION, port: 47777 }] }));
  check('an older card cannot rename them', book.get('TOR-A').name === 'bob');
  check('the live address stays first', book.get('TOR-A').endpoints[0].host === ONION);

  // --- renaming ------------------------------------------------------------

  book.rename(book.get('TOR-A'), { name: 'robert' });
  check('a peer may rename itself', book.get('TOR-A').name === 'robert');

  // --- lookup --------------------------------------------------------------

  check('a friend resolves by exact id', book.resolve('TOR-A')?.id === 'TOR-A');
  check('and case-insensitively', book.resolve('tor-a')?.id === 'TOR-A');
  check('and by name', book.resolve('robert')?.id === 'TOR-A');
  check('and by an id fragment', book.resolve('TORA')?.id === 'TOR-A');
  check('an unknown query resolves to nothing', book.resolve('nobody') === null);
  check('an empty query resolves to nothing', book.resolve('') === null);

  // An ambiguous fragment must resolve to nothing rather than guess.
  book.upsert(card({ id: 'TOR-B', name: 'robert' }));
  check('an ambiguous name resolves to nothing', book.resolve('robert') === null);

  // --- the ui view ---------------------------------------------------------

  const listed = book.list((id) => id === 'TOR-A');
  check('the list covers everyone', listed.length === book.size);
  check('and reports who is online', listed.find((f) => f.id === 'TOR-A').online === true);
  check('and who is not', listed.find((f) => f.id === 'TOR-B').online === false);
  check('and hides bookkeeping', !('sign' in listed[0]));

  // --- persistence ---------------------------------------------------------

  const reloaded = new FriendBook(store).load();
  check('the list survives a reload', reloaded.size === book.size);
  check('with its addresses', reloaded.get('TOR-A').endpoints[0].host === ONION);

  check('removing works', book.delete('TOR-B') === true);
  check('removing twice does not', book.delete('TOR-B') === false);
  check('and the reload reflects it', new FriendBook(store).load().size === book.size);

  fs.rmSync(dir, { recursive: true, force: true });
});
