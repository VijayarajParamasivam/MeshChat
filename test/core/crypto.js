'use strict';

/**
 * Identity derivation, signing, key agreement and sealed frames.
 *
 * The TorChat ID is a hash of a public key, which is what replaces a server-side
 * account registry: nobody can claim your ID without your private key, and there
 * is nothing to check it against because the ID *is* the check.
 */

const c = require('../../src/core/crypto');
const { suite, makePeer, threw } = require('../../scripts/harness');

const { check, run } = suite();

run(async () => {
  const a = makePeer('alice');
  const b = makePeer('bob');

  // --- identity -----------------------------------------------------------

  check('torchat id shape', /^TOR-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(a.profile.id));
  check('torchat id derives from key', c.idMatchesKey(a.profile.id, a.keys.signPublic));
  check('torchat ids differ', a.profile.id !== b.profile.id);
  check('torchat id is stable', c.deriveId(a.keys.signPublic) === a.profile.id);
  check('a mismatched id is caught', !c.idMatchesKey(a.profile.id, b.keys.signPublic));
  check('a malformed key is safe', !c.idMatchesKey(a.profile.id, 'not-a-key'));

  // Crockford base32 drops the letters that get misread aloud.
  check('the id alphabet excludes I, L, O and U', !/[ILOU]/.test(a.profile.id.replace(/^TOR-/, '')));

  // --- signing ------------------------------------------------------------

  const sig = c.sign(a.keys.signPrivate, 'hello');
  check('signature verifies', c.verify(a.keys.signPublic, 'hello', sig));
  check('altered data rejected', !c.verify(a.keys.signPublic, 'hello!', sig));
  check('wrong key rejected', !c.verify(b.keys.signPublic, 'hello', sig));
  check('malformed signature rejected', !c.verify(a.keys.signPublic, 'hello', 'not-a-sig'));
  check('malformed key rejected', !c.verify('not-a-key', 'hello', sig));

  // --- key agreement ------------------------------------------------------

  const keyAB = c.deriveChannelKey(a.keys.boxPrivate, b.keys.boxPublic);
  const keyBA = c.deriveChannelKey(b.keys.boxPrivate, a.keys.boxPublic);
  check('ecdh agrees in both directions', keyAB.equals(keyBA));
  check('the channel key is 256 bits', keyAB.length === 32);

  const other = makePeer('mallory');
  const keyAM = c.deriveChannelKey(a.keys.boxPrivate, other.keys.boxPublic);
  check('a third party derives a different key', !keyAM.equals(keyAB));

  // --- sealed frames ------------------------------------------------------

  const sealed = c.seal(keyAB, { hi: 'there', n: 42 });
  check('seal/open round trip', c.open(keyBA, sealed).hi === 'there');
  check('numbers survive the round trip', c.open(keyBA, sealed).n === 42);

  const twice = c.seal(keyAB, { hi: 'there', n: 42 });
  check('the same payload seals differently each time', !twice.equals(sealed));

  const tampered = Buffer.from(sealed);
  tampered[tampered.length - 1] ^= 0xff;
  check('tampered payload rejected', await threw(() => c.open(keyBA, tampered)));
  check('the wrong key cannot open it', await threw(() => c.open(keyAM, sealed)));
  check('a truncated payload is safe', await threw(() => c.open(keyBA, sealed.subarray(0, 8))));

  // --- misc ---------------------------------------------------------------

  check('nonces differ', c.nonce() !== c.nonce());
  check('message ids differ', c.messageId() !== c.messageId());
});
