'use strict';

/**
 * What to dial, in what order, and how long to wait after a failure.
 *
 * All of it is pure or nearly so, which is the point of the split — the retry
 * policy can be wound forward through a dozen failures here in microseconds
 * rather than being inferred from a log after twenty minutes of real backoff.
 */

const {
  explainDialFailure,
  orderEndpoints,
  raceEndpoints,
  RetryPolicy,
} = require('../../../src/core/roster/dialer');
const { suite, ONION, OTHER_ONION } = require('../../../scripts/harness');

const { check, run } = suite();

const at = (host) => ({ type: 'onion', host, port: 47777 });

run(async () => {
  // --- what may be dialled -------------------------------------------------

  check('an onion is dialable', orderEndpoints([at(ONION)]).length === 1);
  check(
    'ip endpoints are never dialable',
    orderEndpoints([
      { type: 'ip6', host: '2409:40f4::1', port: 47777 },
      { type: 'wan', host: '49.37.1.2', port: 47777 },
      { type: 'lan', host: '192.168.1.5', port: 47777 },
    ]).length === 0
  );
  check('our own onion is not dialled', orderEndpoints([at(ONION)], ONION).length === 0);
  check('but a friend on another onion is', orderEndpoints([at(OTHER_ONION)], ONION).length === 1);
  check('nothing at all is safe', orderEndpoints().length === 0 && orderEndpoints(null).length === 0);

  // --- explaining a failure ------------------------------------------------

  const endpoint = at(ONION);
  check(
    'no tor is explained as ours, not theirs',
    /tor is not running here/.test(explainDialFailure(endpoint, { code: 'ENOTOR', message: '' }))
  );
  check(
    'a timeout suggests they are offline',
    /offline/.test(explainDialFailure(endpoint, { code: 'ETIMEDOUT', message: '' }))
  );
  check(
    'a handshake failure says we reached them',
    /reached them/.test(explainDialFailure(endpoint, { code: 'EHANDSHAKE', message: 'bad proof' }))
  );
  check(
    'an unreachable service is their app being closed',
    /not running/.test(explainDialFailure(endpoint, { message: 'host unreachable' }))
  );
  check(
    'anything else is quoted verbatim',
    /something odd/.test(explainDialFailure(endpoint, { message: 'something odd' }))
  );
  check('the address is always named', explainDialFailure(endpoint, { message: 'x' }).includes(ONION));

  // --- backoff -------------------------------------------------------------

  {
    const retry = new RetryPolicy();
    const id = 'TOR-A';

    check('a friend starts due', retry.due(id));

    retry.penalise(id);
    check('and is not due immediately after a failure', !retry.due(id));
    const first = retry.nextTry.get(id) - Date.now();

    retry.penalise(id);
    const second = retry.nextTry.get(id) - Date.now();
    check('the wait grows', second > first);

    for (let i = 0; i < 20; i++) retry.penalise(id);
    const capped = retry.nextTry.get(id) - Date.now();
    check('the wait is capped', capped <= 300000 + 50);

    check('a distant future is not due', !retry.due(id));
    check('but eventually it is', retry.due(id, Date.now() + 400000));

    retry.reset(id);
    check('a reset makes them due again', retry.due(id));
    check('and forgets the attempt count', !retry.attempts.has(id));
  }

  // --- not repeating yourself ----------------------------------------------

  {
    const retry = new RetryPolicy();
    check('a first failure is worth reporting', retry.shouldReport('TOR-A', 'offline'));
    check('the same failure is not', !retry.shouldReport('TOR-A', 'offline'));
    check('a different one is', retry.shouldReport('TOR-A', 'handshake failed'));
    check('and another friend is tracked separately', retry.shouldReport('TOR-B', 'offline'));
  }

  // --- racing addresses ----------------------------------------------------

  {
    const link = { closed: false, close() { this.closed = true; } };
    const won = await raceEndpoints([at(ONION)], async () => link);
    check('a single address that answers wins', won === link);
  }

  {
    const failures = [];
    const lost = await raceEndpoints(
      [at(ONION)],
      async () => { throw Object.assign(new Error('nope'), { code: 'ETIMEDOUT' }); },
      (endpoint, error) => failures.push(explainDialFailure(endpoint, error))
    );
    check('an address that fails resolves to nothing', lost === null);
    check('and the failure is reported', failures.length === 1);
  }

  {
    // An address that answers at once stops the others being tried at all —
    // their staggered timers are cleared before they fire.
    let started = 0;
    const link = { close() {} };
    await raceEndpoints([at(ONION), at(OTHER_ONION)], async () => {
      started += 1;
      return link;
    });
    check('a quick answer spares the other addresses', started === 1);
  }

  {
    // A straggler only exists when a slow dial is already in flight when a
    // later one wins. It must be closed rather than leaked — nothing will
    // adopt it, and an open circuit nobody owns stays open.
    const slow = { closed: false, close() { this.closed = true; } };
    const quick = { closed: false, close() { this.closed = true; } };

    const won = await raceEndpoints([at(ONION), at(OTHER_ONION)], async (endpoint) => {
      if (endpoint.host === ONION) {
        await new Promise((r) => setTimeout(r, 2500));
        return slow;
      }
      return quick;
    });

    check('the address that answers first wins', won === quick);

    // Wait for the straggler to land rather than guessing how long it takes.
    // A fixed sleep here is a coin flip on a loaded machine.
    const deadline = Date.now() + 8000;
    while (!slow.closed && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }
    check('and the straggler is closed', slow.closed === true);
  }

  check('racing nothing resolves to nothing', (await raceEndpoints([], async () => ({}))) === null);
});
