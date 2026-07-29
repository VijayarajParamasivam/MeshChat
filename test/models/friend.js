'use strict';

/**
 * Someone you know, and — the interesting part — which of two cards wins.
 *
 * Cards are signed but not sequenced, so pasting an old one after a newer one
 * would otherwise reinstate a dead onion ahead of the live one. Identity stays
 * trusted because it is proven by the key; what a card claims about *now* does
 * not, if we already hold something more recent.
 */

const Friend = require('../../src/models/friend');
const { suite, ONION, OTHER_ONION } = require('../../scripts/harness');

const { check, run } = suite();

const card = (over = {}) => ({
  name: 'bob',
  sigil: 'bb',
  sign: 's',
  box: 'b',
  ts: 5000,
  endpoints: [{ host: ONION, port: 47777 }],
  ...over,
});

run(() => {
  // --- a new record -------------------------------------------------------

  {
    const friend = Friend.create('TOR-A');
    check('a new friend has no addresses', friend.endpoints.length === 0);
    check('and keeps its id', friend.id === 'TOR-A');
    check('and is stamped with when we met', friend.addedAt > 0);
  }

  // --- applying a card ----------------------------------------------------

  {
    const friend = Friend.create('TOR-A');
    Friend.applyCard(friend, card({ name: '  bob  ' }));

    check('a card sets the profile', friend.name === 'bob');
    check('a card clamps the profile', friend.sigil === 'bb');
    check('a card sets the keys', friend.sign === 's' && friend.box === 'b');
    check('a card records its time', friend.cardTs === 5000);
    check('a card brings its addresses', friend.endpoints[0].host === ONION);

    const withIp = card({ endpoints: [{ host: '49.37.1.2', port: 47777 }] });
    Friend.applyCard(friend, withIp);
    check('a card cannot smuggle in an ip', friend.endpoints.every((e) => e.host.endsWith('.onion')));
  }

  // --- which card wins ----------------------------------------------------

  {
    const friend = Friend.create('TOR-A');
    Friend.applyCard(friend, card());

    check('an older card is stale', Friend.isStale(friend, card({ ts: 1000 }), false));
    check('a newer card is not', !Friend.isStale(friend, card({ ts: 9000 }), false));
    check('an equally old card is not', !Friend.isStale(friend, card({ ts: 5000 }), false));
    check('a card for someone new is never stale', !Friend.isStale(friend, card({ ts: 1 }), true));
    check('a card with no time is not stale', !Friend.isStale(friend, card({ ts: 0 }), false));

    const older = card({ name: 'imposter', sigil: 'xx', ts: 1000, endpoints: [{ host: OTHER_ONION }] });
    Friend.keepAsFallback(friend, older);
    check('a stale card cannot rename them', friend.name === 'bob');
    check('nor replace their keys', friend.sign === 's');
    check('the live address stays first', friend.endpoints[0].host === ONION);
    check('and the stale one is kept behind it', friend.endpoints[1].host === OTHER_ONION);
  }

  // --- renaming mid-session -----------------------------------------------

  {
    const friend = Friend.create('TOR-A');
    Friend.applyCard(friend, card());

    Friend.rename(friend, { name: 'robert' });
    check('a peer may rename itself', friend.name === 'robert');
    check('and keeps its sigil when given none', friend.sigil === 'bb');

    Friend.rename(friend, { name: '', sigil: '' });
    check('an empty rename changes nothing', friend.name === 'robert' && friend.sigil === 'bb');

    Friend.rename(friend, { name: 'x'.repeat(90) });
    check('a rename is clamped', friend.name.length === 24);
  }

  // --- the view handed to the ui ------------------------------------------

  {
    const friend = Friend.create('TOR-A');
    Friend.applyCard(friend, card());

    const view = Friend.summarise(friend, true);
    check('the ui view reports online', view.online === true);
    check('and carries what it needs', view.id === 'TOR-A' && view.name === 'bob');
    check('and hides bookkeeping', !('cardTs' in view) && !('sign' in view) && !('box' in view));
  }
});
