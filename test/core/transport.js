'use strict';

/**
 * The wire: framing, a mutual-proof handshake, and an encrypted channel.
 *
 * Two of these tests pin rules that cost real bugs. The handshake is *ordered* —
 * whoever dialled speaks first — because Tor discards anything an onion service
 * writes into a rendezvous stream before the dialler's end is joined, silently
 * and with the write reporting success. And a proof is bound to both identities
 * and the protocol, so a signature from one context is not valid in another.
 */

const net = require('net');

const c = require('../../src/core/crypto');
const transport = require('../../src/core/transport');
const { suite, makePeer, threw, frameBytes } = require('../../scripts/harness');

const { check, run } = suite();

/** Connect, speak the protocol by hand, and report what came back. */
function speak(port, { onHello, greet = true, drain = true } = {}) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    const frames = [];
    let buffer = Buffer.alloc(0);

    const finish = (verdict) => {
      socket.destroy();
      resolve({ verdict, frames });
    };

    const timer = setTimeout(() => finish('timeout'), 8000);
    timer.unref();

    socket.on('error', () => finish('closed'));
    socket.on('close', () => finish('closed'));
    if (drain) socket.resume();

    socket.once('connect', () => {
      if (greet) socket.write(frameBytes({ t: 'hello', card: greet.card, nonce: c.nonce() }));
    });

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (buffer.length < 4 + length) return;
        const frame = JSON.parse(buffer.subarray(5, 4 + length).toString('utf8'));
        buffer = buffer.subarray(4 + length);
        frames.push(frame.t);
        if (onHello && frame.t === 'hello') onHello(frame, socket);
      }
    });
  });
}

run(async () => {
  const a = makePeer('alice');
  const b = makePeer('bob');

  // --- a full handshake over a real socket ---------------------------------

  // The inbound link is settled from the connection handler, so its promise has
  // to exist before the listener does. Waiting a fixed 50ms for `listen` to
  // resolve instead of awaiting it read `server` before it was assigned on any
  // machine slow enough to take longer — which is every cold CI runner.
  let arrived;
  const inbound = new Promise((resolve, reject) => {
    arrived = { resolve, reject };
    setTimeout(() => reject(new Error('server link never became ready')), 10000).unref();
  });

  const server = await transport.listen(0, '127.0.0.1', () => a.ctx, (link) => {
    link.once('ready', () => {
      link.on('message', (frame) => {
        if (frame.t === 'msg') link.send({ t: 'msg', id: 'r', body: `echo:${frame.body}` });
      });
      arrived.resolve(link);
    });
    link.once('failed', arrived.reject);
  });

  check('listener binds loopback only', server.address().address === '127.0.0.1');
  const port = server.address().port;

  const raw = net.createConnection({ host: '127.0.0.1', port });
  await new Promise((r) => raw.once('connect', r));
  const dialed = await transport.overStream(raw, b.ctx, a.profile.id);
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
  const wrong = net.createConnection({ host: '127.0.0.1', port });
  await new Promise((r) => wrong.once('connect', r));
  check('identity mismatch refused', await threw(() =>
    transport.overStream(wrong, b.ctx, b.profile.id, 4000)
  ));

  dialed.close();
  served.close();
  server.close();

  // --- who speaks first ----------------------------------------------------
  //
  // Tor drops an onion service's writes before the stream is joined, so the
  // side that accepted must stay silent until spoken to. Verified against a
  // live circuit: a marker written on accept never arrived, while the same
  // marker written four seconds later arrived in 380ms.

  const quiet = await transport.listen(0, '127.0.0.1', () => b.ctx, () => {});
  const quietPort = quiet.address().port;

  const unprompted = await new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: quietPort });
    let got = 0;
    socket.on('error', () => {});
    socket.on('data', () => { got += 1; });
    setTimeout(() => { socket.destroy(); resolve(got); }, 600);
  });
  check('the responder does not greet unprompted', unprompted === 0);

  const answered = await speak(quietPort, {
    greet: { card: a.cardCode },
    onHello: (frame, socket) => {
      socket.write(frameBytes({
        t: 'proof',
        sig: c.sign(a.keys.signPrivate, frame.nonce), // unbound, as an old build sent
      }));
    },
  });
  check('it greets once spoken to', answered.frames[0] === 'hello');
  check('and proves itself only after that', answered.frames[1] === 'proof');
  check('a proof over the bare nonce is rejected', answered.verdict === 'closed');

  // --- a hello with no challenge -------------------------------------------

  const noNonce = await new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: quietPort });
    socket.resume();
    socket.on('error', () => resolve('closed'));
    socket.on('close', () => resolve('closed'));
    setTimeout(() => resolve('open'), 6000).unref();
    socket.once('connect', () => socket.write(frameBytes({ t: 'hello', card: a.cardCode })));
  });
  check('a hello with no challenge is refused', noNonce === 'closed');

  quiet.close();

  // --- framing and timeouts ------------------------------------------------

  const link = new transport.Link(new net.Socket(), b.ctx, { handshakeTimeoutMs: 90000 });
  check('the handshake honours the caller budget', link.handshakeTimer._idleTimeout === 90000);
  check('a link starts closed to application traffic', link.send({ t: 'msg' }) === false);
  link.close();
  check('closing is idempotent', (link.close(), true));
});
