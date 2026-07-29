'use strict';

/**
 * The contact card is the only thing that ever crosses between two people out of
 * band, so it is parsed as hostile input: a pasted string of unknown origin that
 * has to prove it was made by whoever it claims.
 */

const c = require('../../src/core/crypto');
const card = require('../../src/core/card');
const { suite, makePeer, threw, ONION } = require('../../scripts/harness');

const { check, run } = suite();

run(async () => {
  const a = makePeer('alice');
  const code = card.create(a.profile, a.keys, [{ type: 'onion', host: ONION, port: 47777 }]);

  // --- round trip ---------------------------------------------------------

  check('code carries the TORCHAT1 prefix', code.startsWith(card.PREFIX));

  const parsed = card.parse(code);
  check('card round trips the id', parsed.id === a.profile.id);
  check('card round trips the keys', parsed.sign === a.keys.signPublic);
  check('card round trips endpoints', parsed.endpoints[0].host === ONION);
  check('card round trips the port', parsed.endpoints[0].port === 47777);
  check('card carries a timestamp', typeof parsed.ts === 'number');

  check('whitespace in a pasted code is tolerated', card.parse(`  ${code}\n`).id === a.profile.id);

  // --- forgery ------------------------------------------------------------

  const rewrite = (mutate) => {
    const raw = JSON.parse(Buffer.from(code.slice(card.PREFIX.length), 'base64url').toString());
    mutate(raw);
    return card.PREFIX + Buffer.from(JSON.stringify(raw)).toString('base64url');
  };

  check(
    'an altered name is rejected',
    await threw(() => card.parse(rewrite((raw) => { raw.name = 'mallory'; })))
  );
  check(
    'an altered endpoint is rejected',
    await threw(() => card.parse(rewrite((raw) => { raw.endpoints[0].host = 'evil.onion'; })))
  );
  check(
    'a swapped id is rejected',
    await threw(() => card.parse(rewrite((raw) => { raw.id = 'TOR-AAAA-AAAA-AAAA'; })))
  );
  check(
    'a stripped signature is rejected',
    await threw(() => card.parse(rewrite((raw) => { delete raw.sig; })))
  );

  // --- malformed input ----------------------------------------------------

  check('junk is rejected', await threw(() => card.parse('hello world')));
  check('an empty string is rejected', await threw(() => card.parse('')));
  check('null is rejected', await threw(() => card.parse(null)));
  check('a truncated code is rejected', await threw(() => card.parse(code.slice(0, 40))));
  check(
    'an unknown version is rejected',
    await threw(() => card.parse(rewrite((raw) => { raw.v = 99; })))
  );

  // --- freshness ----------------------------------------------------------
  //
  // The timestamp decides which of two cards for the same person is current, so
  // one dated in the future would outrank every real card they ever make again.

  const original = Date.now;
  Date.now = () => original() + 30 * 86400000;
  const future = card.create(a.profile, a.keys, []);
  Date.now = original;

  const refused = await threw(() => card.parse(future));
  check('a card dated in the future is refused', /future/i.test(refused || ''));

  // --- canonical form -----------------------------------------------------
  //
  // Both ends must serialise identically or every signature check would fail.

  check(
    'key order does not change the canonical form',
    card.canonical({ b: 1, a: 2 }) === card.canonical({ a: 2, b: 1 })
  );
  check('nested objects are canonicalised too', card.canonical({ x: { b: 1, a: 2 } }) === '{"x":{"a":2,"b":1}}');
  check('undefined becomes null', card.canonical(undefined) === 'null');

  // A card built with no endpoints is still valid — it just cannot be dialled.
  check('an endpointless card still parses', card.parse(card.create(a.profile, a.keys, [])).endpoints.length === 0);

  check('a name is clamped on the way out', card.parse(
    card.create({ ...a.profile, name: 'x'.repeat(90) }, a.keys, [])
  ).name.length === 24);

  check('the id must match its key', c.idMatchesKey(parsed.id, parsed.sign));
});
