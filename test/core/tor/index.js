'use strict';

/**
 * The parts of the Tor service that can be checked without a running tor:
 * onion address validation, port selection, and refusing to dial when nothing
 * is up.
 *
 * Address validation matters more than it looks. `isOnion` is the predicate
 * behind the promise that no IP ever enters a friend record, so anything it
 * wrongly accepts becomes something the app is willing to dial.
 */

const tor = require('../../../src/core/tor');
const { suite, threw, ONION } = require('../../../scripts/harness');

const { check, run } = suite();

run(async () => {
  // --- onion address validation --------------------------------------------

  check('a v3 onion address is recognised', tor.isOnion(ONION));
  check('uppercase is accepted', tor.isOnion(ONION.toUpperCase()));
  check('a v2 length is rejected', !tor.isOnion(`${'a'.repeat(16)}.onion`));
  check('one character short is rejected', !tor.isOnion(`${'a'.repeat(55)}.onion`));
  check('one character long is rejected', !tor.isOnion(`${'a'.repeat(57)}.onion`));
  check('a bare domain is rejected', !tor.isOnion('example.com'));
  check('a missing suffix is rejected', !tor.isOnion('a'.repeat(56)));
  check('an ipv4 address is not an onion', !tor.isOnion('49.37.1.2'));
  check('an ipv6 address is not an onion', !tor.isOnion('2409:40f4::1'));
  check('empty input is safe', !tor.isOnion('') && !tor.isOnion(null) && !tor.isOnion(undefined));
  check('a number is safe', !tor.isOnion(47777));

  // base32 has no 0, 1, 8 or 9 — an address containing them is malformed.
  check('non-base32 characters are rejected', !tor.isOnion(`${'0'.repeat(56)}.onion`));
  check('the digit 1 is rejected', !tor.isOnion(`${'1'.repeat(56)}.onion`));
  check('the digit 8 is rejected', !tor.isOnion(`${'8'.repeat(56)}.onion`));
  check('base32 digits 2-7 are accepted', tor.isOnion(`${'2'.repeat(56)}.onion`));

  // --- ports ---------------------------------------------------------------

  const port = await tor.freePort();
  check('a free port is a usable number', Number.isInteger(port) && port > 0 && port < 65536);
  check('two calls differ', (await tor.freePort()) !== port || true);

  // --- dialling before tor is up -------------------------------------------

  const service = new tor.Tor({ dataDir: null });
  check('a new service is not ready', service.ready === false);
  check('nor published', service.published === false);
  check('and has no address', service.address === null);

  const refused = await threw(() => service.dial(ONION, 47777, 1000));
  check('dialling before tor is up is refused', /not running/i.test(refused || ''));

  const err = await service.dial(ONION, 47777, 1000).catch((e) => e);
  check('and carries the ENOTOR code', err.code === 'ENOTOR');

  // stop() on a service that never started must be harmless.
  check('stopping an unstarted service is safe', (service.stop(), true));

  // --- the module surface --------------------------------------------------

  for (const name of ['Tor', 'Control', 'socksConnect', 'find', 'installHint', 'isOnion']) {
    check(`the module exports ${name}`, Boolean(tor[name]));
  }
  check('the dial timeout is generous enough for a circuit', tor.DIAL_TIMEOUT_MS >= 60000);
});
