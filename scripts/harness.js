'use strict';

/**
 * The only file under test/ that does not mirror a source file.
 *
 * Every suite needs the same three things — a way to assert, a tally, and an
 * exit code — and duplicating them into seventeen files would mean seventeen
 * chances for one of them to quietly stop counting failures.
 *
 * Deliberately not node:test. The suites here are plain scripts that run under
 * any Node 20+, print one line per assertion, and exit non-zero on failure,
 * which is all CI needs and keeps the output readable when a circuit test takes
 * a minute to say anything.
 */

const c = require('../src/core/crypto');

/**
 * Start a suite.
 * @returns {{check: Function, done: Function, run: Function}}
 */
function suite() {
  let failures = 0;

  const check = (name, condition) => {
    console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}`);
    if (!condition) failures += 1;
    return Boolean(condition);
  };

  const done = () => {
    console.log(failures ? `\n${failures} failing` : '\nall good');
    process.exit(failures ? 1 : 0);
  };

  /** Run an async body, report, and never let a throw look like a pass. */
  const run = (body) =>
    Promise.resolve()
      .then(body)
      .then(done)
      .catch((err) => {
        console.error('\nharness crashed:', err);
        process.exit(1);
      });

  return { check, done, run };
}

/** A complete identity with keys, for tests that need two of anything. */
function makePeer(name, endpoints = []) {
  const card = require('../src/core/card');
  const signing = c.generateSigningPair();
  const box = c.generateBoxPair();

  const keys = {
    signPrivate: signing.privateKey,
    signPublic: c.exportPublic(signing.publicKey),
    boxPrivate: box.privateKey,
    boxPublic: c.exportPublic(box.publicKey),
  };
  const profile = { id: c.deriveId(keys.signPublic), name, sigil: name[0] };

  return {
    profile,
    keys,
    cardCode: card.create(profile, keys, endpoints),
    get ctx() {
      return { identity: profile, keys, cardCode: this.cardCode };
    },
  };
}

/** Did this throw? Returns the message, or null if it did not. */
async function threw(body) {
  try {
    await body();
    return null;
  } catch (err) {
    return err.message;
  }
}

/** A frame written the way Link writes it, for hand-rolled protocol tests. */
function frameBytes(value, tag = 0) {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  const header = Buffer.alloc(5);
  header.writeUInt32BE(body.length + 1, 0);
  header.writeUInt8(tag, 4);
  return Buffer.concat([header, body]);
}

const ONION = `${'a'.repeat(56)}.onion`;
const OTHER_ONION = `${'b'.repeat(56)}.onion`;

module.exports = { suite, makePeer, threw, frameBytes, ONION, OTHER_ONION };
