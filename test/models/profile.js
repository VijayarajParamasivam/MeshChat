'use strict';

/**
 * Display names and sigils arrive from someone else's machine, so nothing about
 * them is trusted. The clamping used to be written out by hand in four places
 * with four slightly different opinions — two trimmed, two did not.
 */

const Profile = require('../../src/models/profile');
const { suite } = require('../../scripts/harness');

const { check, run } = suite();

run(() => {
  check('a name is clamped', Profile.name('x'.repeat(80)).length === Profile.MAX_NAME);
  check('a name is trimmed', Profile.name('   bob   ') === 'bob');
  check('an empty name falls back', Profile.name('') === Profile.DEFAULT_NAME);
  check('a whitespace-only name falls back', Profile.name('    ') === Profile.DEFAULT_NAME);
  check('a name can fall back to a previous one', Profile.name('', 'previous') === 'previous');
  check('a name survives intact', Profile.name('bob') === 'bob');

  check('a sigil is clamped', Profile.sigil('abcdef') === 'ab');
  check('an empty sigil falls back', Profile.sigil('') === Profile.DEFAULT_SIGIL);
  check('a sigil can fall back to a previous one', Profile.sigil('', 'zz') === 'zz');

  const p = Profile.create('TOR-A', '  bob  ', 'bbbb');
  check('a profile keeps its id verbatim', p.id === 'TOR-A');
  check('a profile clamps what it is given', p.name === 'bob' && p.sigil === 'bb');
});
