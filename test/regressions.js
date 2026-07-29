'use strict';

/**
 * Regressions.
 *
 * Every case here is a bug that shipped while the rest of the suite stayed
 * green, so each test names the wrong behaviour it pins down rather than just
 * the right one. They need no Tor and no network: the control-port parser, the
 * handshake, and the message store are all driven directly.
 */

const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const c = require('../src/core/crypto');
const card = require('../src/core/card');
const store = require('../src/core/store');
const tor = require('../src/core/tor');
const transport = require('../src/core/transport');

let failures = 0;
function check(name, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}`);
  if (!condition) failures++;
}

const ONION = `${'a'.repeat(56)}.onion`;

function makePeer(name) {
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
    ctx: {
      identity: profile,
      keys,
      cardCode: card.create(profile, keys, [{ type: 'onion', host: ONION, port: 47777 }]),
    },
  };
}

(async () => {
  // --- the control port's reply parser ------------------------------------

  {
    // A continuation line containing three digits and a space used to terminate
    // the reply there: the caller got a truncated answer, or a rejection quoting
    // a status code that was really part of a log message.
    const control = new tor.Control(0);
    const replies = [];
    control.waiting.push({ resolve: (lines) => replies.push(lines), reject: () => {} });
    control._onData('250-ServiceID=abc\r\n250-Note=we waited 250 seconds\r\n250 OK\r\n');

    check('a status code inside a line does not end the reply', replies.length === 1);
    check('the whole reply survives', (replies[0] || []).length === 3);
    check('nothing is left over', control.buffer === '');
  }

  {
    // A command that timed out left its slot in the queue. The late reply then
    // shifted that slot and answered the *next* caller with it, and from there
    // every reply belonged to the wrong command.
    const control = new tor.Control(0);
    const abandoned = { abandoned: true, resolve: () => {}, reject: () => {} };
    let secondGot = null;
    control.waiting.push(abandoned);
    control.waiting.push({ resolve: (lines) => { secondGot = lines; }, reject: () => {} });

    control._onData('250 LATE\r\n'); // belongs to the abandoned command
    check('a late reply is absorbed by its own slot', secondGot === null);

    control._onData('250 MINE\r\n');
    check('the next command still gets its own reply', /MINE/.test((secondGot || []).join('')));
  }

  {
    // SETEVENTS replaces the subscription list rather than adding to it, so
    // unsubscribing one thing must not cancel everything else.
    const control = new tor.Control(0);
    const sent = [];
    control.socket = { write: (line) => sent.push(line.trim()) };
    control.send = async function (command) {
      sent.push(command);
      return [];
    };

    await control.subscribe('HS_DESC');
    await control.subscribe('STATUS_CLIENT');
    await control.unsubscribe('HS_DESC');

    check('unsubscribing keeps the other events', sent[2] === 'SETEVENTS STATUS_CLIENT');
  }

  // --- the handshake ------------------------------------------------------

  {
    // The proof used to sign the bare nonce, so a signature said nothing about
    // who made it or who it was for. It is now bound to both identities.
    const alice = makePeer('alice');
    const bob = makePeer('bob');

    const server = await transport.listen(0, '127.0.0.1', () => bob.ctx, () => {});
    const { port } = server.address();

    // Speak the protocol by hand: greet as the dialler must, then answer their
    // challenge with a signature over the bare nonce — exactly what an older
    // build would have sent.
    const result = await new Promise((resolve) => {
      const socket = net.createConnection({ host: '127.0.0.1', port });
      let buffer = Buffer.alloc(0);
      const done = (value) => {
        socket.destroy();
        resolve(value);
      };
      setTimeout(() => done('timeout'), 8000).unref();

      const writeFrame = (value) => {
        const body = Buffer.from(JSON.stringify(value), 'utf8');
        const header = Buffer.alloc(5);
        header.writeUInt32BE(body.length + 1, 0);
        header.writeUInt8(0, 4);
        socket.write(Buffer.concat([header, body]));
      };

      socket.on('error', () => done('error'));
      socket.on('close', () => done('closed'));
      socket.once('connect', () =>
        writeFrame({ t: 'hello', card: alice.ctx.cardCode, nonce: c.nonce() })
      );

      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const length = buffer.readUInt32BE(0);
          if (buffer.length < 4 + length) return;
          const body = buffer.subarray(5, 4 + length);
          buffer = buffer.subarray(4 + length);
          const frame = JSON.parse(body.toString('utf8'));

          if (frame.t === 'hello') {
            writeFrame({ t: 'proof', sig: c.sign(alice.keys.signPrivate, frame.nonce) }); // unbound
          }
        }
      });
    });

    check('a proof over the bare nonce is rejected', result === 'closed');
    server.close();
  }

  {
    // A hello with no nonce was signed as the literal string "undefined" — the
    // same challenge for every such peer.
    const bob = makePeer('bob');
    const server = await transport.listen(0, '127.0.0.1', () => bob.ctx, () => {});
    const { port } = server.address();
    const alice = makePeer('alice');

    const closed = await new Promise((resolve) => {
      const socket = net.createConnection({ host: '127.0.0.1', port });
      setTimeout(() => resolve(false), 8000).unref();
      socket.on('close', () => resolve(true));
      socket.on('error', () => resolve(true));
      // Drain, or the peer's unread hello keeps the stream paused and Node
      // never delivers the close that follows it.
      socket.resume();
      socket.once('connect', () => {
        const payload = Buffer.from(
          JSON.stringify({ t: 'hello', card: alice.ctx.cardCode }), // no nonce
          'utf8'
        );
        const header = Buffer.alloc(5);
        header.writeUInt32BE(payload.length + 1, 0);
        header.writeUInt8(0, 4);
        socket.write(Buffer.concat([header, payload]));
      });
    });

    check('a hello with no challenge is refused', closed === true);
    server.close();
  }

  {
    // The one that stopped the app working over Tor at all.
    //
    // Tor discards anything an onion service writes into a rendezvous stream
    // before the CONNECTED cell reaches the dialler — silently, with the write
    // returning true. The Link used to greet from its constructor on both
    // sides, so the responder's hello was destroyed every time and the dialler
    // saw its `proof` arrive with no `hello` before it. Verified against a live
    // circuit: a marker written on accept never arrived, the same marker
    // written four seconds later arrived in 380ms.
    //
    // Locally there is no Tor to drop anything, so what is pinned here is the
    // rule that fixes it: the side that accepted must stay silent until spoken
    // to, and must then send hello before proof.
    const bob = makePeer('bob');
    const alice = makePeer('alice');

    const server = await transport.listen(0, '127.0.0.1', () => bob.ctx, () => {});
    const { port } = server.address();

    const frames = await new Promise((resolve) => {
      const socket = net.createConnection({ host: '127.0.0.1', port });
      const got = [];
      let buffer = Buffer.alloc(0);
      let spokeAt = null;

      // Stay silent for half a second. Anything that arrives in that window is
      // the responder greeting unprompted.
      const unprompted = [];
      setTimeout(() => {
        unprompted.push(...got);
        spokeAt = Date.now();
        const hello = Buffer.from(
          JSON.stringify({ t: 'hello', card: alice.ctx.cardCode, nonce: c.nonce() }),
          'utf8'
        );
        const header = Buffer.alloc(5);
        header.writeUInt32BE(hello.length + 1, 0);
        header.writeUInt8(0, 4);
        socket.write(Buffer.concat([header, hello]));
      }, 500);

      setTimeout(() => {
        socket.destroy();
        resolve({ unprompted, after: got.filter((f) => spokeAt) });
      }, 3000).unref();

      socket.on('error', () => {});
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const length = buffer.readUInt32BE(0);
          if (buffer.length < 4 + length) return;
          const body = buffer.subarray(5, 4 + length);
          buffer = buffer.subarray(4 + length);
          got.push(JSON.parse(body.toString('utf8')).t);
        }
      });
    });

    check('the responder does not greet unprompted', frames.unprompted.length === 0);
    check('it greets once spoken to', frames.after[0] === 'hello');
    check('and proves itself only after that', frames.after[1] === 'proof');
    server.close();
  }

  {
    // The Link's own fixed 45s timer always beat a longer caller budget, so a
    // handshake that was merely slow across six relays was reported failed.
    const bob = makePeer('bob');
    const link = new transport.Link(new net.Socket(), bob.ctx, { handshakeTimeoutMs: 90000 });
    const delay = link.handshakeTimer._idleTimeout;
    link.close();
    check('the handshake honours the caller budget', delay === 90000);
  }

  // --- cards --------------------------------------------------------------

  {
    // The timestamp decides which of two cards is current, so one dated in the
    // future would outrank every real card that person ever makes again.
    const peer = makePeer('clockskew');
    const original = Date.now;
    Date.now = () => original() + 30 * 86400000;
    const future = card.create(peer.profile, peer.keys, [
      { type: 'onion', host: ONION, port: 47777 },
    ]);
    Date.now = original;

    let refused = null;
    try {
      card.parse(future);
    } catch (err) {
      refused = err.message;
    }
    check('a card dated in the future is refused', /future/i.test(refused || ''));
  }

  // --- the message store --------------------------------------------------

  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-regress-'));
    store.init(dir);
    const peerId = 'TOR-TEST-TEST-TEST';

    // "sent" only ever meant socket.write() accepted the bytes. A message
    // written into a circuit that died was never retried and never reported.
    store.appendMessage(peerId, { id: 'a', ts: 1, body: 'queued', mine: true, state: 'queued' });
    store.appendMessage(peerId, { id: 'b', ts: 2, body: 'sent', mine: true, state: 'sent' });
    store.appendMessage(peerId, { id: 'd', ts: 3, body: 'done', mine: true, state: 'delivered' });

    const pending = store.undelivered(peerId).map((m) => m.id);
    check('an unacknowledged sent message is still retried', pending.includes('b'));
    check('a queued message is still retried', pending.includes('a'));
    check('a delivered message is not resent', !pending.includes('d'));

    // IDs are chosen by whoever composed the message, so the two directions
    // share an ID space. A peer must not be able to touch our half of it.
    store.appendMessage(peerId, { id: 'x', ts: 4, body: 'ours', mine: true, state: 'sent' });
    check('an inbound id does not collide with ours', store.hasMessage(peerId, 'x') === false);

    store.appendMessage(peerId, { id: 'x', ts: 5, body: 'theirs', mine: false, state: 'received' });
    check('a genuine resend is recognised', store.hasMessage(peerId, 'x') === true);

    const acked = store.updateMessage(peerId, 'x', { state: 'delivered' }, true);
    check('an ack matches our copy, not theirs', acked && acked.body === 'ours');

    // Restoring a backup must not carry the previous identity's history over.
    store.resetCache();
    fs.rmSync(path.join(dir, 'messages'), { recursive: true, force: true });
    fs.mkdirSync(path.join(dir, 'messages'), { recursive: true });
    check('resetCache drops the in-memory history', store.recentMessages(peerId).length === 0);

    fs.rmSync(dir, { recursive: true, force: true });
  }

  // --- the roster ---------------------------------------------------------

  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torchat-regress2-'));
    store.init(dir);

    const { TorChat } = require('../src/core/roster');
    const engine = new TorChat();
    const peer = makePeer('ghost');

    // A link that died between 'ready' and adoption used to be stored anyway.
    // Link.close() has already dropped its listeners, so the 'close' handler
    // never fired, the friend sat in this.links forever, and _redialAll skipped
    // them for having a "live" link. Only a restart brought them back.
    const dead = {
      closed: true,
      peer: { ...peer.profile, sign: peer.keys.signPublic, box: peer.keys.boxPublic, endpoints: [] },
      close() {},
      send() { return false; },
      on() {},
      once() {},
    };
    engine._adopt(dead);

    check('a dead link is not adopted', engine.links.has(peer.profile.id) === false);
    check('and the friend is left retryable', engine.nextTry.has(peer.profile.id));

    // /try takes what a person actually types.
    engine.friends.set(peer.profile.id, {
      id: peer.profile.id,
      name: 'ghost',
      sigil: 'g',
      endpoints: [],
    });
    const byName = engine.resolve('ghost');
    check('a friend resolves by name', byName && byName.id === peer.profile.id);

    const report = await engine.probe('ghost');
    check('probe accepts free text', report.name === 'ghost');
    check('probe reports the friend it tried', report.id === peer.profile.id);
    check('probe explains the failure', report.ok === false && report.reasons.length > 0);

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log(failures ? `\n${failures} failing` : '\nall good');
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
