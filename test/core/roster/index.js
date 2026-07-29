'use strict';

/**
 * The engine, and the privacy claims it makes to its user.
 *
 * These are asserted rather than trusted. There is no longer a private *mode* to
 * switch on: the engine has no access to an IP address to publish, and these
 * tests exist to make that stay true if somebody reintroduces one.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const card = require('../../../src/core/card');
const identity = require('../../../src/core/identity');
const store = require('../../../src/core/store');
const { TorChat, ONION_PORT } = require('../../../src/core/roster');
const { suite, makePeer, threw, ONION } = require('../../../scripts/harness');

const { check, run } = suite();

run(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-engine-'));
  store.init(dir);
  store.resetCache();

  // addFriend compares an incoming card against our own identity, so one has to
  // exist for that path to be exercised rather than throwing on a null.
  identity.create('tester', 'T');

  const engine = new TorChat();
  engine.onion = ONION;
  engine.tor = { ready: true };

  // --- what we publish -----------------------------------------------------

  const published = engine._localEndpoints();
  check('only one endpoint is published', published.length === 1);
  check('and it is the onion', published[0].type === 'onion' && published[0].host === ONION);
  check('the advertised port is the virtual onion port', published[0].port === ONION_PORT);
  check(
    'no ip of any kind appears in the card',
    !JSON.stringify(published).match(/\d+\.\d+\.\d+\.\d+|ip6|lan|wan/)
  );

  // With no onion yet there is simply nothing to advertise.
  const fresh = new TorChat();
  check('an unpublished engine advertises nothing', fresh._localEndpoints().length === 0);

  // --- what we accept ------------------------------------------------------

  const friend = { id: 'TOR-X', endpoints: [] };
  engine._mergeEndpoints(friend, [
    { type: 'ip6', host: '2409:40f4::1', port: 47777 },
    { type: 'lan', host: '192.168.1.5', port: 47777 },
    { type: 'wan', host: '49.37.1.2', port: 47777 },
    { type: 'onion', host: ONION, port: ONION_PORT },
  ]);
  check('ip endpoints are dropped on merge', friend.endpoints.length === 1);
  check('the onion survives', friend.endpoints[0].host === ONION);

  // --- what we dial --------------------------------------------------------

  check(
    'ip endpoints are never dialable',
    engine._orderEndpoints([
      { type: 'ip6', host: '2409:40f4::1', port: 47777 },
      { type: 'wan', host: '49.37.1.2', port: 47777 },
    ]).length === 0
  );
  check(
    'our own onion is not dialled',
    engine._orderEndpoints([{ type: 'onion', host: ONION, port: ONION_PORT }]).length === 0
  );

  // --- adding a friend -----------------------------------------------------

  const stranger = makePeer('legacy', [{ type: 'ip6', host: '2409:40f4::1', port: 47777 }]);
  const refusedCard = await threw(() => engine.addFriend(stranger.cardCode));
  check('a card with no onion address is refused', /onion/i.test(refusedCard || ''));

  check('junk is refused', await threw(() => engine.addFriend('hello')));
  check('an empty code is refused', await threw(() => engine.addFriend('')));

  const own = card.create(identity.profile(), identity.getKeys(), [
    { type: 'onion', host: ONION, port: ONION_PORT },
  ]);
  const ownCode = await threw(() => engine.addFriend(own));
  check('your own code is refused', /your own/i.test(ownCode || ''));

  // --- a link that died before adoption ------------------------------------
  //
  // Link.close() has already emitted 'close' and dropped its listeners, so a
  // handler registered after the fact never fires. Storing a dead link left the
  // friend "online" forever and _redialAll skipped them; only a restart helped.

  const peer = makePeer('ghost');
  const dead = {
    closed: true,
    peer: {
      ...peer.profile,
      sign: peer.keys.signPublic,
      box: peer.keys.boxPublic,
      endpoints: [],
    },
    close() {},
    send: () => false,
    on() {},
    once() {},
  };
  engine._adopt(dead);
  check('a dead link is not adopted', engine.links.has(peer.profile.id) === false);
  check('and the friend is left retryable', engine.nextTry.has(peer.profile.id));

  // --- probing -------------------------------------------------------------

  engine.friends.set(peer.profile.id, {
    id: peer.profile.id,
    name: 'ghost',
    sigil: 'g',
    endpoints: [],
  });

  check('a friend resolves by name', engine.resolve('ghost')?.id === peer.profile.id);

  const report = await engine.probe('ghost');
  check('probe accepts free text', report.name === 'ghost');
  check('probe reports the friend it tried', report.id === peer.profile.id);
  check('probe explains the failure', report.ok === false && report.reasons.length > 0);
  check('probe on a stranger throws', await threw(() => engine.probe('nobody')));

  // --- status --------------------------------------------------------------

  const status = engine.status();
  check('status reports the onion', status.onion === ONION);
  check('status reports the virtual port', status.port === ONION_PORT);
  check('status counts friends', status.friends === engine.friends.size);
  check('status never carries an ip', !JSON.stringify(status).match(/\d+\.\d+\.\d+\.\d+/));

  // --- messages need a friend ----------------------------------------------

  check('sending to a stranger throws', await threw(() => engine.sendText('TOR-NOBODY', 'hi')));

  fs.rmSync(dir, { recursive: true, force: true });
});
