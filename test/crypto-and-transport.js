'use strict';

/**
 * Covers the parts that don't need Electron: identity derivation, signing,
 * key agreement, sealed frames, contact cards, and a full two-peer handshake
 * over a real TCP socket.
 *
 * Deliberately dependency-free so it runs anywhere Node runs.
 */

const net = require('net');

const c = require('../src/core/crypto');
const card = require('../src/core/card');
const transport = require('../src/core/transport');

const PORT = 47901;

let failures = 0;
function check(name, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}`);
  if (!condition) failures++;
}

function makePeer(name) {
  const signing = c.generateSigningPair();
  const box = c.generateBoxPair();
  const keys = {
    signPrivate: signing.privateKey,
    signPublic: c.exportPublic(signing.publicKey),
    boxPrivate: box.privateKey,
    boxPublic: c.exportPublic(box.publicKey),
  };
  return { profile: { id: c.deriveId(keys.signPublic), name, sigil: name[0] }, keys };
}

(async function main() {
  // --- identity -----------------------------------------------------------
  const a = makePeer('alice');
  const b = makePeer('bob');

  check('torchat id shape', /^TOR-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(a.profile.id));
  check('torchat id derives from key', c.idMatchesKey(a.profile.id, a.keys.signPublic));
  check('torchat ids differ', a.profile.id !== b.profile.id);
  check('torchat id is stable', c.deriveId(a.keys.signPublic) === a.profile.id);

  // --- signing ------------------------------------------------------------
  const sig = c.sign(a.keys.signPrivate, 'hello');
  check('signature verifies', c.verify(a.keys.signPublic, 'hello', sig));
  check('altered data rejected', !c.verify(a.keys.signPublic, 'hello!', sig));
  check('wrong key rejected', !c.verify(b.keys.signPublic, 'hello', sig));
  check('malformed signature rejected', !c.verify(a.keys.signPublic, 'hello', 'not-a-sig'));

  // --- channel ------------------------------------------------------------
  const keyAB = c.deriveChannelKey(a.keys.boxPrivate, b.keys.boxPublic);
  const keyBA = c.deriveChannelKey(b.keys.boxPrivate, a.keys.boxPublic);
  check('ecdh agrees in both directions', keyAB.equals(keyBA));

  const sealed = c.seal(keyAB, { hi: 'there', n: 42 });
  check('seal/open round trip', c.open(keyBA, sealed).hi === 'there');

  const tampered = Buffer.from(sealed);
  tampered[tampered.length - 1] ^= 0xff;
  let tamperCaught = false;
  try {
    c.open(keyBA, tampered);
  } catch {
    tamperCaught = true;
  }
  check('tampered payload rejected', tamperCaught);

  // --- contact cards ------------------------------------------------------
  const codeA = card.create(a.profile, a.keys, [
    { type: 'lan', host: '127.0.0.1', port: PORT },
  ]);
  check('code carries the TORCHAT1 prefix', codeA.startsWith('TORCHAT1.'));

  const parsed = card.parse(codeA);
  check('card round trips the id', parsed.id === a.profile.id);
  check('card round trips endpoints', parsed.endpoints[0].port === PORT);

  let forgeCaught = false;
  try {
    const raw = JSON.parse(Buffer.from(codeA.slice(6), 'base64url').toString());
    raw.name = 'mallory';
    card.parse(`TORCHAT1.${Buffer.from(JSON.stringify(raw)).toString('base64url')}`);
  } catch {
    forgeCaught = true;
  }
  check('altered card rejected', forgeCaught);

  let junkCaught = false;
  try {
    card.parse('hello world');
  } catch {
    junkCaught = true;
  }
  check('junk code rejected', junkCaught);

  // --- live handshake -----------------------------------------------------
  const ctxA = { identity: a.profile, keys: a.keys, cardCode: codeA };
  const ctxB = {
    identity: b.profile,
    keys: b.keys,
    cardCode: card.create(b.profile, b.keys, []),
  };

  let server;
  const inbound = new Promise((resolve, reject) => {
    setTimeout(() => reject(new Error('server link never became ready')), 10000);
    transport
      .listen(PORT, '127.0.0.1', () => ctxA, (link) => {
        link.once('ready', () => {
          link.on('message', (frame) => {
            if (frame.t === 'msg') link.send({ t: 'msg', id: 'r', body: `echo:${frame.body}` });
          });
          resolve(link);
        });
        link.once('failed', reject);
      })
      .then((s) => {
        server = s;
        // Loopback only: nothing but our own Tor should ever reach this.
        check('listener binds loopback only', s.address().address === '127.0.0.1');
      })
      .catch(reject);
  });

  // No dial() any more — every connection arrives as an open stream from Tor.
  // A plain socket stands in for the circuit; the handshake cannot tell.
  const raw = net.createConnection({ host: '127.0.0.1', port: PORT });
  await new Promise((r) => raw.once('connect', r));
  const dialed = await transport.overStream(raw, ctxB, a.profile.id);
  const served = await inbound;

  check('dialer learned the server identity', dialed.peer.id === a.profile.id);
  check('server learned the dialer identity', served.peer.id === b.profile.id);
  check('both sides report ready', dialed.ready && served.ready);

  const echoed = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no echo came back')), 5000);
    dialed.on('message', (frame) => {
      if (frame.t === 'msg') {
        clearTimeout(timer);
        resolve(frame.body);
      }
    });
    dialed.send({ t: 'msg', id: '1', body: 'ping over the wire' });
  });
  check('encrypted round trip', echoed === 'echo:ping over the wire');

  // Dialling while expecting the wrong identity must be refused.
  let mismatchCaught = false;
  try {
    const wrong = net.createConnection({ host: '127.0.0.1', port: PORT });
    await new Promise((r) => wrong.once('connect', r));
    await transport.overStream(wrong, ctxB, b.profile.id, 4000);
  } catch {
    mismatchCaught = true;
  }
  check('identity mismatch refused', mismatchCaught);

  dialed.close();
  served.close();
  if (server) server.close();

  console.log(failures ? `\n${failures} FAILURE(S)` : '\nall checks passed');
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.error('harness crashed:', err);
  process.exit(1);
});
