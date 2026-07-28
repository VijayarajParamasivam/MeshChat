'use strict';

/**
 * Covers the hole-punching transport: window alignment, the two-way punch
 * itself, and the reliability layer that has to exist because UDP provides
 * none. Ends with a full identity handshake carried over a punched session,
 * which is the property that actually matters — the crypto above must not be
 * able to tell it is no longer running on TCP.
 *
 * Everything runs over loopback. That proves the mechanics, not that any
 * particular carrier permits them; scripts/punch-test.js is for that.
 */

const c = require('../src/core/crypto');
const card = require('../src/core/card');
const punch = require('../src/core/punch');
const transport = require('../src/core/transport');

const PORT_A = 47911;
const PORT_B = 47912;

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
  const profile = { id: c.deriveMeshId(keys.signPublic), name, sigil: name[0] };
  return {
    profile,
    keys,
    ctx: {
      identity: profile,
      keys,
      cardCode: card.create(profile, keys, [{ type: 'ip6', host: '::1', port: 1 }]),
    },
  };
}

function collect(stream) {
  const chunks = [];
  stream.on('data', (chunk) => chunks.push(chunk));
  return () => Buffer.concat(chunks);
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async function main() {
  // --- window alignment ---------------------------------------------------
  //
  // The whole scheme rests on both machines choosing the same instant with no
  // channel to agree through, so this arithmetic is load-bearing.
  const period = punch.PUNCH_PERIOD_MS;
  check('window is zero exactly on a boundary', punch.msUntilWindow(period * 4, period) === 0);
  check('window counts down to the next boundary', punch.msUntilWindow(period * 4 + 1000, period) === period - 1000);
  check('window never exceeds the period', punch.msUntilWindow(Date.now(), period) < period);

  // Two machines a second apart must land in the same window, not adjacent ones.
  const now = period * 10 + 500;
  const skewed = now + 1000;
  check(
    'a second of clock skew lands in the same window',
    Math.abs(punch.msUntilWindow(now, period) - punch.msUntilWindow(skewed, period)) === 1000
  );

  // --- address normalisation ----------------------------------------------
  check('ipv4 normalises to v4-mapped', punch.normaliseHost('10.0.0.5') === '::ffff:10.0.0.5');
  check('ipv6 passes through', punch.normaliseHost('2001:db8::1') === '2001:db8::1');
  check('zone index is stripped', punch.normaliseHost('fe80::1%7') === 'fe80::1');
  check(
    'keys match regardless of ipv4 form',
    punch.keyFor('10.0.0.5', 1) === punch.keyFor('::ffff:10.0.0.5', 1)
  );

  // --- the punch itself ---------------------------------------------------
  const hubA = await new punch.Hub(PORT_A).start();
  const hubB = await new punch.Hub(PORT_B).start();

  // Each side receives whatever the other punches through unprompted.
  const inboundB = new Promise((resolve) => hubB.once('session', resolve));

  // `aligned: false` fires immediately; the alignment maths is checked above and
  // waiting up to 30s for a real boundary would make the suite useless.
  const [streamA, streamB] = await Promise.all([
    hubA.punch('::1', PORT_B, { aligned: false }),
    inboundB,
  ]);

  check('punching opens a session on the initiating side', !!streamA && !streamA.destroyed);
  check('the punched-at side gets a session too', !!streamB && !streamB.destroyed);
  check('sessions point at each other', streamB.port === PORT_A);

  // Punching the same peer twice must reuse the session rather than build a
  // second one over the same tuple.
  const again = await hubA.punch('::1', PORT_B, { aligned: false });
  check('a repeat punch reuses the open session', again === streamA);

  // --- reliability --------------------------------------------------------
  const readB = collect(streamB);
  const readA = collect(streamA);

  streamA.write(Buffer.from('hello over udp', 'utf8'));
  await wait(200);
  check('a small write arrives', readB().toString('utf8') === 'hello over udp');

  streamB.write(Buffer.from('and back again', 'utf8'));
  await wait(200);
  check('traffic flows the other way too', readA().toString('utf8') === 'and back again');

  // A payload several times the datagram limit exercises the split, the
  // sequence numbers and the reassembly all at once.
  const big = Buffer.alloc(punch.MAX_PAYLOAD * 5 + 137);
  for (let i = 0; i < big.length; i++) big[i] = i % 251;

  const readBigB = collect(streamB);
  streamA.write(big);
  await wait(800);
  const gotBig = readBigB();
  check('an oversized payload is split and reassembled', gotBig.equals(big));

  // Ordering under reordering: feed frames to the receiver backwards and check
  // it still delivers them in sequence. This is the case UDP creates and TCP
  // never does, so it is worth driving directly rather than hoping loopback
  // produces it.
  const solo = new punch.UdpStream(hubA, '::1', 59999);
  const readSolo = collect(solo);
  const frame = (seq, text) => {
    const body = Buffer.alloc(4 + text.length);
    body.writeUInt32BE(seq, 0);
    body.write(text, 4, 'utf8');
    return body;
  };

  solo._receive(punch.types.DATA, frame(3, 'ccc'));
  solo._receive(punch.types.DATA, frame(2, 'bbb'));
  check('a gap holds delivery back', readSolo().length === 0);

  solo._receive(punch.types.DATA, frame(1, 'aaa'));
  check('filling the gap releases everything in order', readSolo().toString('utf8') === 'aaabbbccc');

  solo._receive(punch.types.DATA, frame(2, 'bbb'));
  check('a duplicate is discarded', readSolo().toString('utf8') === 'aaabbbccc');
  solo.destroy();

  // --- a real handshake over the punched path -----------------------------
  const alice = makePeer('alice');
  const bob = makePeer('bob');

  const hubC = await new punch.Hub(47913).start();
  const hubD = await new punch.Hub(47914).start();

  const inboundD = new Promise((resolve) => hubD.once('session', resolve));
  const [cStream, dStream] = await Promise.all([
    hubC.punch('::1', 47914, { aligned: false }),
    inboundD,
  ]);

  const [linkA, linkB] = await Promise.all([
    transport.overStream(cStream, alice.ctx, bob.profile.id),
    transport.overStream(dStream, bob.ctx, alice.profile.id),
  ]);

  check('both ends complete the handshake over udp', linkA.ready && linkB.ready);
  check('alice identifies bob', linkA.peer.id === bob.profile.id);
  check('bob identifies alice', linkB.peer.id === alice.profile.id);

  const delivered = new Promise((resolve) => linkB.once('message', resolve));
  linkA.send({ t: 'msg', body: 'punched through' });
  const frameIn = await delivered;
  check('an encrypted message survives the punched path', frameIn.body === 'punched through');

  // Dialling someone who is not who we expected must still be refused, exactly
  // as over TCP — the transport changing must not weaken the identity check.
  const hubE = await new punch.Hub(47915).start();
  const hubF = await new punch.Hub(47916).start();
  const inboundF = new Promise((resolve) => hubF.once('session', resolve));
  const [eStream, fStream] = await Promise.all([
    hubE.punch('::1', 47916, { aligned: false }),
    inboundF,
  ]);

  const mallory = makePeer('mallory');
  const rejected = transport
    .overStream(eStream, alice.ctx, mallory.profile.id, 3000)
    .then(() => false)
    .catch(() => true);
  transport.overStream(fStream, bob.ctx).catch(() => {});

  check('a peer with the wrong identity is rejected', await rejected);

  linkA.close();
  linkB.close();
  for (const hub of [hubA, hubB, hubC, hubD, hubE, hubF]) hub.stop();

  console.log(failures ? `\n${failures} failing` : '\nall good');
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
