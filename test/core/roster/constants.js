'use strict';

/**
 * The engine's timings.
 *
 * Constants rarely deserve a suite, but these encode assumptions about a
 * transport where a single round trip crosses six relays. A value tuned for TCP
 * silently abandons connections that were about to succeed, and nothing else in
 * the app would report it as anything other than "they are offline".
 */

const constants = require('../../../src/core/roster/constants');
const Endpoint = require('../../../src/models/endpoint');
const { suite } = require('../../../scripts/harness');

const { check, run } = suite();

run(() => {
  const {
    ONION_PORT,
    REDIAL_INTERVAL_MS,
    MAX_BACKOFF_MS,
    FIRST_BACKOFF_MS,
    DIAL_STAGGER_MS,
    DIAL_TIMEOUT_MS,
    MAX_ENDPOINTS,
  } = constants;

  // The onion port has one definition. Re-exporting a *copy* would let the two
  // drift, and a friend would dial a port nothing is listening on.
  check('the onion port comes from the endpoint model', ONION_PORT === Endpoint.ONION_PORT);
  check('and the endpoint cap does too', MAX_ENDPOINTS === Endpoint.MAX_ENDPOINTS);
  check('the onion port is a valid port', ONION_PORT > 0 && ONION_PORT < 65536);

  // Every timing is a positive number of milliseconds.
  for (const [name, value] of Object.entries(constants)) {
    if (!name.endsWith('_MS')) continue;
    check(`${name} is a positive duration`, Number.isFinite(value) && value > 0);
  }

  check('backoff grows from its floor to its ceiling', FIRST_BACKOFF_MS < MAX_BACKOFF_MS);
  check(
    'the redial sweep is faster than the backoff ceiling',
    REDIAL_INTERVAL_MS < MAX_BACKOFF_MS
  );

  // A dial has to outlast circuit construction, which takes tens of seconds on
  // a congested mobile connection — measured at over 30s here.
  check('a dial waits long enough for a circuit', DIAL_TIMEOUT_MS >= 60000);
  check(
    'staggered addresses are all tried within one dial',
    DIAL_STAGGER_MS * MAX_ENDPOINTS < DIAL_TIMEOUT_MS
  );
});
