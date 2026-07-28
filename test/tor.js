'use strict';

/**
 * Covers the parts of the Tor path that can be checked without Tor installed:
 * the SOCKS5 client's wire format, onion address validation, and the control
 * port's reply parser.
 *
 * The SOCKS test runs against a fake proxy rather than a real one, which is the
 * point — it asserts the exact bytes we put on the wire. The single most
 * important of those is that the destination goes out as a *domain name*: if it
 * ever became an IP, this machine would be resolving .onion addresses locally
 * and leaking who it is trying to reach, while every test about privacy
 * elsewhere carried on passing.
 */

const net = require('net');

const tor = require('../src/core/tor');

let failures = 0;
function check(name, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}`);
  if (!condition) failures++;
}

const ONION = 'a'.repeat(56) + '.onion';

/**
 * A pretend SOCKS5 proxy that records the request it was given and then behaves
 * like a successful tunnel.
 */
function fakeSocks({ status = 0x00, echo = null } = {}) {
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

          const reply = Buffer.from([0x05, status, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
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

(async function main() {
  // --- onion address validation -------------------------------------------
  check('a v3 onion address is recognised', tor.isOnion(ONION));
  check('uppercase is accepted', tor.isOnion(ONION.toUpperCase()));
  check('a v2 length is rejected', !tor.isOnion(`${'a'.repeat(16)}.onion`));
  check('a bare domain is rejected', !tor.isOnion('example.com'));
  check('an ipv6 address is not an onion', !tor.isOnion('2409:40f4::1'));
  check('empty input is safe', !tor.isOnion('') && !tor.isOnion(null));
  // base32 has no 0, 1, 8 or 9 — an address containing them is malformed.
  check('non-base32 characters are rejected', !tor.isOnion(`${'0'.repeat(56)}.onion`));

  // --- SOCKS5 request format ----------------------------------------------
  const proxy = await fakeSocks();
  const socket = await tor.socksConnect(proxy.port, ONION, 47777, 5000);

  check('offers version 5 with no authentication', proxy.seen.greeting.equals(Buffer.from([0x05, 0x01, 0x00])));
  check('issues a CONNECT command', proxy.seen.version === 0x05 && proxy.seen.command === 0x01);
  check('sends the onion as a domain name, not an ip', proxy.seen.addressType === 0x03);
  check('sends the address intact', proxy.seen.host === ONION);
  check('sends the port big-endian', proxy.seen.port === 47777);

  // The returned socket must be a working tunnel.
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
  const eagerSocket = await tor.socksConnect(eager.port, ONION, 47777, 5000);
  const first = await new Promise((resolve) => {
    eagerSocket.once('data', (chunk) => resolve(chunk.toString('utf8')));
  });
  check('data sent alongside the reply is not swallowed', first === 'HELLO');
  eagerSocket.destroy();
  eager.server.close();

  // --- failure reporting ---------------------------------------------------
  const refusing = await fakeSocks({ status: 0x04 });
  let reported = '';
  try {
    await tor.socksConnect(refusing.port, ONION, 47777, 5000);
  } catch (err) {
    reported = err.message;
  }
  check('an unreachable onion is explained', /offline/i.test(reported));
  refusing.server.close();

  // --- control port replies ------------------------------------------------
  //
  // Replies are multi-line with a "250-" prefix until the final "250 OK", and
  // ADD_ONION returns the address and key across separate lines.
  const control = new tor.Control(0);
  const collected = [];
  control.socket = { write() {} };
  const pending = new Promise((resolve, reject) => {
    control.waiting.push({ resolve, reject });
  });
  pending.then((lines) => collected.push(...lines)).catch(() => {});

  control._onData(
    '250-ServiceID=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx\r\n' +
      '250-PrivateKey=ED25519-V3:SOMEKEYMATERIAL\r\n' +
      '250 OK\r\n'
  );
  await pending;

  check('a multi-line control reply is assembled', collected.length === 3);
  check(
    'the service id is recoverable',
    /ServiceID=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx/.test(collected[0])
  );
  check('the private key is recoverable', /PrivateKey=ED25519-V3:/.test(collected[1]));

  const failing = new tor.Control(0);
  failing.socket = { write() {} };
  const rejected = new Promise((resolve, reject) => {
    failing.waiting.push({ resolve, reject });
  })
    .then(() => false)
    .catch(() => true);
  failing._onData('515 Authentication failed\r\n');
  check('an error status rejects rather than resolves', await rejected);

  // --- install guidance ----------------------------------------------------
  check('there is a usable hint when tor is missing', tor.installHint().length > 0);

  // --- privacy invariants --------------------------------------------------
  //
  // These are the claims private mode makes to the user, so they are asserted
  // rather than trusted. Each one is a separate way the app could reveal where
  // this machine is, and leaving any single one working would undo the others.
  const os = require('os');
  const fs = require('fs');
  const path = require('path');
  const store = require('../src/core/store');
  const { Mesh } = require('../src/core/roster');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshchat-private-'));
  store.init(dir);
  store.writeSettings({ private: true, tor: true });

  const mesh = new Mesh();
  mesh.port = 47777;
  mesh.onion = ONION;
  mesh.tor = { ready: true };

  check('private mode is read from settings', mesh.private === true);
  check('enabling private mode implies tor', mesh.torEnabled === true);

  const published = mesh._localEndpoints();
  check('only one endpoint is published', published.length === 1);
  check('and it is the onion', published[0].type === 'onion' && published[0].host === ONION);
  check(
    'no ip of any kind appears in the card',
    !JSON.stringify(published).match(/\d+\.\d+\.\d+\.\d+|ip6|lan|wan/)
  );

  // The stored card of a friend may well contain IPs from before private mode.
  // They must be ignored, not merely deprioritised — dialling one would reveal
  // this machine's address to whatever answered.
  const mixed = [
    { type: 'ip6', host: '2409:40f4::1', port: 47777 },
    { type: 'lan', host: '192.168.1.5', port: 47777 },
    { type: 'wan', host: '49.37.1.2', port: 47777 },
    { type: 'onion', host: ONION, port: 47777 },
  ];
  const ordered = mesh._orderEndpoints(mixed);
  check('stored ip endpoints are discarded in private mode', ordered.length === 1);
  check('the onion is what remains', ordered[0].type === 'onion');

  let refusedIp = null;
  try {
    await mesh._dialEndpoint({ type: 'ip6', host: '2409:40f4::1', port: 47777 }, 'MESH-X');
  } catch (err) {
    refusedIp = err.code;
  }
  check('dialling a plain ip is refused outright', refusedIp === 'EPRIVATE');

  // With private mode off, the ordering should prefer speed but still keep the
  // onion as the fallback that always works.
  store.writeSettings({ private: false, tor: true });
  const open = mesh._orderEndpoints(mixed);
  check('normally every endpoint stays available', open.length === 4);
  check('direct ipv6 is preferred for speed', open[0].type === 'ip6');
  check('the onion sorts last as the slow certainty', open[open.length - 1].type === 'onion');

  // An onion endpoint is useless without Tor running, and offering it would
  // stall every dial for the full circuit timeout before failing.
  mesh.tor = null;
  check(
    'onion endpoints are dropped when tor is not running',
    !mesh._orderEndpoints(mixed).some((e) => e.type === 'onion')
  );

  fs.rmSync(dir, { recursive: true, force: true });

  console.log(failures ? `\n${failures} failing` : '\nall good');
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
