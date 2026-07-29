'use strict';

/**
 * The SOCKS5 client, checked byte for byte against a fake proxy.
 *
 * The single most important assertion here is that the destination leaves as a
 * *domain name*. If it ever became an IP, this machine would be resolving
 * .onion addresses locally and leaking who it is trying to reach, while every
 * other privacy test in the suite carried on passing.
 */

const net = require('net');

const { socksConnect, buildConnectRequest, SocksError } = require('../../../src/core/tor/socks');
const { suite, threw, ONION } = require('../../../scripts/harness');

const { check, run } = suite();

/**
 * A pretend SOCKS5 proxy that records the request it was given and then behaves
 * like a successful tunnel.
 */
function fakeSocks({ status = 0x00, echo = null, addressType = 0x01 } = {}) {
  return new Promise((resolve) => {
    const seen = {};
    const server = net.createServer((socket) => {
      let stage = 'greeting';

      socket.on('data', (chunk) => {
        if (stage === 'greeting') {
          seen.greeting = Buffer.from(chunk);
          socket.write(Buffer.from([0x05, 0x00]));
          stage = 'request';
          return;
        }

        if (stage === 'request') {
          seen.request = Buffer.from(chunk);
          seen.version = chunk[0];
          seen.command = chunk[1];
          seen.addressType = chunk[3];
          const length = chunk[4];
          seen.host = chunk.subarray(5, 5 + length).toString('utf8');
          seen.port = chunk.readUInt16BE(5 + length);

          const reply =
            addressType === 0x03
              ? Buffer.concat([
                  Buffer.from([0x05, status, 0x00, 0x03, 3]),
                  Buffer.from('abc'),
                  Buffer.from([0, 0]),
                ])
              : Buffer.from([0x05, status, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);

          // Bytes riding along with the reply must survive the handshake.
          socket.write(echo ? Buffer.concat([reply, Buffer.from(echo, 'utf8')]) : reply);
          stage = 'tunnel';
          return;
        }

        socket.write(chunk); // echo, so the tunnel can be shown to work
      });
    });

    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen }));
  });
}

run(async () => {
  // --- request format -----------------------------------------------------

  const proxy = await fakeSocks();
  const socket = await socksConnect(proxy.port, ONION, 47777, 5000);

  check(
    'offers version 5 with no authentication',
    proxy.seen.greeting.equals(Buffer.from([0x05, 0x01, 0x00]))
  );
  check('issues a CONNECT command', proxy.seen.version === 0x05 && proxy.seen.command === 0x01);
  check('sends the onion as a domain name, not an ip', proxy.seen.addressType === 0x03);
  check('sends the address intact', proxy.seen.host === ONION);
  check('sends the port big-endian', proxy.seen.port === 47777);

  const echoed = await new Promise((resolve) => {
    socket.once('data', (chunk) => resolve(chunk.toString('utf8')));
    socket.write('ping');
  });
  check('the resolved socket carries traffic', echoed === 'ping');
  socket.destroy();
  proxy.server.close();

  // --- bytes arriving with the reply --------------------------------------
  //
  // Tor can deliver the peer's first frame in the same packet as the SOCKS
  // reply. Dropping it would lose the handshake's opening move and strand the
  // connection, which would look like an unreachable peer rather than a bug.

  const eager = await fakeSocks({ echo: 'HELLO' });
  const eagerSocket = await socksConnect(eager.port, ONION, 47777, 5000);
  const first = await new Promise((resolve) => {
    eagerSocket.once('data', (chunk) => resolve(chunk.toString('utf8')));
  });
  check('data sent alongside the reply is not swallowed', first === 'HELLO');
  eagerSocket.destroy();
  eager.server.close();

  // A domain-typed bound address is a different length and must also be
  // consumed exactly, or the tunnel starts mid-frame.
  const domainBound = await fakeSocks({ echo: 'HELLO', addressType: 0x03 });
  const domainSocket = await socksConnect(domainBound.port, ONION, 47777, 5000);
  const afterDomain = await new Promise((resolve) => {
    domainSocket.once('data', (chunk) => resolve(chunk.toString('utf8')));
  });
  check('a domain bound address is consumed exactly', afterDomain === 'HELLO');
  domainSocket.destroy();
  domainBound.server.close();

  // --- failure reporting ---------------------------------------------------

  const refusing = await fakeSocks({ status: 0x04 });
  const reported = await threw(() => socksConnect(refusing.port, ONION, 47777, 5000));
  check('an unreachable onion is explained', /offline/i.test(reported || ''));
  refusing.server.close();

  const refused = await fakeSocks({ status: 0x05 });
  const refusedMsg = await threw(() => socksConnect(refused.port, ONION, 47777, 5000));
  check('a refused connection is explained', /refused/i.test(refusedMsg || ''));
  refused.server.close();

  // Nothing listening at all.
  const dead = await threw(() => socksConnect(1, ONION, 47777, 3000));
  check('an absent proxy is reported', Boolean(dead));

  // --- the request builder -------------------------------------------------

  const request = buildConnectRequest(ONION, 47777);
  check('the builder marks a domain name', request[3] === 0x03);
  check('the builder writes the length', request[4] === ONION.length);
  check('the builder writes the port last', request.readUInt16BE(5 + ONION.length) === 47777);
  check('an overlong host is refused', await threw(() => buildConnectRequest('x'.repeat(300), 1)));
  check('the refusal is a SocksError', (() => {
    try {
      buildConnectRequest('x'.repeat(300), 1);
      return false;
    } catch (err) {
      return err instanceof SocksError;
    }
  })());
});
