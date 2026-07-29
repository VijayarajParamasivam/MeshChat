'use strict';

/**
 * A minimal SOCKS5 client, just enough to ask Tor for a connection.
 *
 * The address is sent as a *domain name*, not an IP, which matters for more than
 * convenience: it means Tor resolves the .onion inside the network and this
 * machine never performs a lookup that could leak who we are trying to reach.
 * Resolving locally first would defeat the entire point.
 */

const net = require('net');

/** Tor is slow. Circuits take seconds to build; onion rendezvous takes longer. */
const DIAL_TIMEOUT_MS = 90000;

const VERSION = 0x05;
const CMD_CONNECT = 0x01;
const ADDR_IPV4 = 0x01;
const ADDR_DOMAIN = 0x03;
const ADDR_IPV6 = 0x04;

const REPLY_ERRORS = {
  1: 'general failure',
  2: 'connection not allowed',
  3: 'network unreachable',
  4: 'host unreachable — the onion service is probably offline',
  5: 'connection refused',
  6: 'TTL expired',
  7: 'command not supported',
  8: 'address type not supported',
};

/**
 * A fault in the SOCKS conversation itself, as opposed to a socket blowing up.
 *
 * Carrying its own message means the orchestrator can re-raise it verbatim
 * rather than wrapping it, so the text a user sees stays exactly the text
 * written here — `roster` matches on some of it to tell "they're offline" from
 * "something is wrong at our end".
 */
class SocksError extends Error {
  constructor(message, code = 'ETORDIAL') {
    super(message);
    this.name = 'SocksError';
    this.code = code;
  }
}

/** The CONNECT request for a hostname. Pure; throws if the name cannot fit. */
function buildConnectRequest(host, port) {
  const name = Buffer.from(host, 'utf8');
  if (name.length > 255) throw new SocksError('onion address is too long');

  const request = Buffer.alloc(7 + name.length);
  request.writeUInt8(VERSION, 0);
  request.writeUInt8(CMD_CONNECT, 1);
  request.writeUInt8(0x00, 2); // reserved
  request.writeUInt8(ADDR_DOMAIN, 3);
  request.writeUInt8(name.length, 4);
  name.copy(request, 5);
  request.writeUInt16BE(port, 5 + name.length);
  return request;
}

/**
 * How many bytes of bound address follow the reply header.
 *
 * The value is of no use to us, but it has to be consumed to leave the stream
 * positioned at the first tunnelled byte.
 */
async function boundAddressLength(type, readExactly) {
  if (type === ADDR_IPV4) return 4;
  if (type === ADDR_IPV6) return 16;
  if (type === ADDR_DOMAIN) return (await readExactly(1))[0];
  throw new SocksError('bad SOCKS address type');
}

/**
 * Read exactly `n` bytes, leaving anything beyond them untouched.
 *
 * This is why the socket is never put in flowing mode: Tor routinely delivers
 * the peer's first frame in the same segment as the SOCKS reply, and that frame
 * is the handshake's opening move. A 'data' listener would hand us those bytes
 * with no way to give them back — the connection would then wait forever for a
 * `hello` that had already arrived, looking exactly like an unreachable peer.
 * Reading precise amounts in paused mode leaves the remainder in the stream's
 * own buffer, where the caller's handler picks it up the moment it attaches.
 */
function exactReader(socket, isSettled) {
  return (n) =>
    new Promise((done) => {
      const attempt = () => {
        if (isSettled()) return;
        const chunk = socket.read(n);
        if (chunk) return done(chunk);
        socket.once('readable', attempt);
      };
      attempt();
    });
}

/** Open a connection through Tor's SOCKS port. */
function socksConnect(socksPort, host, port, timeoutMs = DIAL_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: socksPort });
    let settled = false;

    const fail = (message, code = 'ETORDIAL') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
      const error = new Error(message);
      error.code = code;
      reject(error);
    };

    const timer = setTimeout(
      () => fail(`tor did not answer within ${Math.round(timeoutMs / 1000)}s`, 'ETIMEDOUT'),
      timeoutMs
    );

    socket.on('error', (err) => fail(`socks: ${err.message}`, err.code));
    socket.on('close', () => fail('tor closed the connection during the handshake'));

    const readExactly = exactReader(socket, () => settled);

    /** The whole conversation. Throws SocksError on any protocol fault. */
    const negotiate = async () => {
      // Version 5, one method offered, "no authentication".
      socket.write(Buffer.from([VERSION, 0x01, 0x00]));

      const greeting = await readExactly(2);
      if (settled) return false;
      if (greeting[0] !== VERSION || greeting[1] !== 0x00) {
        throw new SocksError('tor refused the SOCKS handshake');
      }

      socket.write(buildConnectRequest(host, port));

      const head = await readExactly(4); // version, status, reserved, type
      if (settled) return false;
      if (head[0] !== VERSION) throw new SocksError('bad SOCKS reply');

      const status = head[1];
      if (status !== 0x00) {
        throw new SocksError(`tor could not connect: ${REPLY_ERRORS[status] || `code ${status}`}`);
      }

      const addressBytes = await boundAddressLength(head[3], readExactly);
      if (settled) return false;

      await readExactly(addressBytes + 2); // address plus the bound port
      return !settled;
    };

    socket.on('connect', async () => {
      try {
        if (!(await negotiate())) return;

        settled = true;
        clearTimeout(timer);

        // The 'readable' listener is ours alone and must go, or it would race
        // the caller for the tunnelled bytes. The 'error' and 'close' handlers
        // stay: both call fail(), which returns immediately now that settled is
        // true, and leaving them means the socket is never momentarily without
        // an 'error' listener between here and the Link that adopts it. An
        // unheard 'error' on a socket is a thrown exception, not a no-op.
        socket.removeAllListeners('readable');

        resolve(socket);
      } catch (err) {
        // A SocksError is already phrased for a human; anything else is an
        // unexpected fault and gets labelled as coming from this layer.
        if (err instanceof SocksError) fail(err.message, err.code);
        else fail(`socks: ${err.message}`);
      }
    });
  });
}

module.exports = { socksConnect, SocksError, buildConnectRequest, DIAL_TIMEOUT_MS };
