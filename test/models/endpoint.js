'use strict';

/**
 * The most load-bearing model in the app.
 *
 * `mergeOnions` is the single choke point every address passes through — from a
 * pasted card, from a live peer, from the friend file on disk. The promise that
 * no IP can ever enter a friend record and be dialled rests entirely on it, so
 * it is asserted rather than trusted.
 */

const Endpoint = require('../../src/models/endpoint');
const { suite, ONION, OTHER_ONION } = require('../../scripts/harness');

const { check, run } = suite();

run(() => {
  // --- construction -------------------------------------------------------

  check('an onion endpoint keeps its host', Endpoint.onion(ONION).host === ONION);
  check('and defaults its port', Endpoint.onion(ONION).port === Endpoint.ONION_PORT);
  check('a bad port falls back', Endpoint.onion(ONION, 'x').port === Endpoint.ONION_PORT);
  check('an explicit port survives', Endpoint.onion(ONION, 1234).port === 1234);
  check('the type is always onion', Endpoint.onion(ONION).type === 'onion');

  // --- what may be dialled ------------------------------------------------

  check('an onion is dialable', Endpoint.isDialable({ host: ONION }));
  check('an ipv4 address is not', !Endpoint.isDialable({ host: '49.37.1.2' }));
  check('an ipv6 address is not', !Endpoint.isDialable({ host: '2409:40f4::1' }));
  check('a lan address is not', !Endpoint.isDialable({ host: '192.168.1.5' }));
  check('a hostname is not', !Endpoint.isDialable({ host: 'example.com' }));
  check('our own onion is not', !Endpoint.isDialable({ host: ONION }, ONION));
  check('nothing at all is not', !Endpoint.isDialable(null));

  // --- merging ------------------------------------------------------------

  {
    const merged = Endpoint.mergeOnions(
      [
        { type: 'wan', host: '49.37.1.2', port: 47777 },
        { type: 'ip6', host: '2409:40f4::1', port: 47777 },
        { type: 'lan', host: '192.168.1.5', port: 47777 },
        { type: 'onion', host: ONION, port: 47777 },
      ],
      []
    );
    check('merging drops every ip', merged.length === 1);
    check('and keeps the onion', merged[0].host === ONION);
    check('and normalises its type', merged[0].type === 'onion');
  }

  {
    const merged = Endpoint.mergeOnions([{ host: OTHER_ONION }], [{ host: ONION }]);
    check('incoming addresses come first', merged[0].host === OTHER_ONION);
    check('existing ones stay behind them', merged[1].host === ONION);
  }

  {
    const dupe = { host: ONION, port: 47777 };
    check('duplicates collapse', Endpoint.mergeOnions([dupe], [dupe]).length === 1);
    check(
      'the same host on another port is kept',
      Endpoint.mergeOnions([{ host: ONION, port: 1 }], [{ host: ONION, port: 2 }]).length === 2
    );
  }

  {
    const many = Array.from({ length: 10 }, (_, i) => ({
      host: `${String.fromCharCode(97 + i).repeat(56)}.onion`,
      port: 47777,
    }));
    check('the list is capped', Endpoint.mergeOnions(many, []).length === Endpoint.MAX_ENDPOINTS);
  }

  check('merging nothing is safe', Endpoint.mergeOnions().length === 0);
  check('a malformed entry is skipped', Endpoint.mergeOnions([null, {}, { host: '' }]).length === 0);

  // --- card form ----------------------------------------------------------

  const forCard = Endpoint.forCard({ type: 'onion', host: ONION, port: '47777' });
  check('a card endpoint keeps its declared type', forCard.type === 'onion');
  check('and numbers its port', forCard.port === 47777);
});
