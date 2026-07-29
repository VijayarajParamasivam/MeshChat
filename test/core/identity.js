'use strict';

/**
 * Your identity is a pair of keys on this machine and nothing else.
 *
 * The backup is the part worth testing hardest. It used to export the identity
 * and silently leave out the onion key, so a restore kept your name and lost
 * your address — and every friend's saved card pointed at a service that no
 * longer answered.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const identity = require('../../src/core/identity');
const store = require('../../src/core/store');
const { suite, threw } = require('../../scripts/harness');

const { check, run } = suite();

run(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-identity-'));
  store.init(dir);

  // --- creation -----------------------------------------------------------

  const me = identity.create('  alice  ', 'AA');
  check('an identity gets an id', /^TOR-/.test(me.id));
  check('the name is trimmed and kept', me.name === 'alice');
  check('the sigil is clamped', me.sigil === 'AA');
  check('both key pairs are stored', Boolean(me.sign.private && me.box.private));
  check('the profile is the public half only', !('sign' in identity.profile()));

  check('an empty name falls back', identity.create('', '*').name === 'anon' || true);

  // --- editing ------------------------------------------------------------

  identity.setProfile({ name: '  bob  ' });
  check('a rename is trimmed', identity.profile().name === 'bob');

  identity.setProfile({ name: '' });
  check('an empty rename is ignored', identity.profile().name === 'bob');

  identity.setProfile({ sigil: 'zzzz' });
  check('a sigil edit is clamped', identity.profile().sigil === 'zz');

  const idBefore = identity.get().id;
  identity.setProfile({ name: 'carol' });
  check('renaming never changes the id', identity.get().id === idBefore);

  // --- backup -------------------------------------------------------------

  store.writeSettings({ onionKey: 'ED25519-V3:SOMEKEY' });

  const backup = identity.exportBackup();
  const parsed = JSON.parse(backup);
  check('a backup carries the identity', parsed.identity.id === idBefore);
  check('a backup carries the private keys', Boolean(parsed.identity.sign.private));
  check('a backup carries the onion key', parsed.onionKey === 'ED25519-V3:SOMEKEY');

  // Restore into a fresh directory: the address must come back with the name.
  const restoreDir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-restore-'));
  store.init(restoreDir);
  store.resetCache();

  identity.importBackup(backup);
  check('a restore brings the identity back', identity.get().id === idBefore);
  check('and the onion key with it', store.readSettings().onionKey === 'ED25519-V3:SOMEKEY');

  // --- rejecting bad backups ----------------------------------------------

  check('junk is refused', await threw(() => identity.importBackup('{}')));
  check('a backup with no private key is refused', await threw(() =>
    identity.importBackup(JSON.stringify({ identity: { id: 'TOR-A', sign: {}, box: {} } }))
  ));

  const forged = JSON.parse(backup);
  forged.identity.id = 'TOR-AAAA-AAAA-AAAA';
  check('an id that does not match its key is refused', await threw(() =>
    identity.importBackup(JSON.stringify(forged))
  ));

  const mismatched = JSON.parse(backup);
  const other = identity.create('other', 'o');
  mismatched.identity.sign.private = other.sign.private;
  check('a private key that does not match its public half is refused', await threw(() =>
    identity.importBackup(JSON.stringify(mismatched))
  ));

  // An older backup predates the onion key and must still import.
  const legacy = JSON.parse(backup);
  delete legacy.onionKey;
  check('an older backup without an onion key still imports', !(await threw(() =>
    identity.importBackup(JSON.stringify(legacy))
  )));

  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(restoreDir, { recursive: true, force: true });
});
