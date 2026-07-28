'use strict';

/**
 * The wire: plain TCP straight between two machines, with a mutual-proof
 * handshake and an encrypted channel on top.
 *
 * Frame layout is [4-byte big-endian length][1-byte tag][body]. The tag says
 * whether the body is plaintext handshake JSON (0) or an AES-GCM sealed payload
 * (1). Tagging each frame rather than tracking a mode avoids a race where one
 * side starts encrypting before the other has finished its handshake.
 *
 * The handshake proves possession, not just knowledge: each side sends a random
 * nonce and must return a signature over the other's nonce. Copying somebody's
 * public contact card therefore gets you nowhere — you'd need their private key.
 */

const net = require('net');
const { EventEmitter } = require('events');

const c = require('./crypto');
const card = require('./card');

const TAG_PLAIN = 0;
const TAG_SEALED = 1;
const MAX_FRAME = 1024 * 1024;
const HANDSHAKE_TIMEOUT_MS = 10000;
const PING_INTERVAL_MS = 20000;
const PING_TIMEOUT_MS = 60000;

class Link extends EventEmitter {
  /**
   * @param {net.Socket} socket
   * @param {object} ctx      { identity, keys, cardCode }
   * @param {object} options  { expectId } when we dialled a specific friend
   */
  constructor(socket, ctx, { expectId = null } = {}) {
    super();
    this.socket = socket;
    this.ctx = ctx;
    this.expectId = expectId;

    this.peer = null;
    this.ready = false;
    this.closed = false;

    this.channelKey = null;
    this.myNonce = c.nonce();
    this.theyProved = false;
    this.weProved = false;

    this.buffer = Buffer.alloc(0);
    this.lastSeen = Date.now();

    socket.setKeepAlive(true, 15000);
    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('error', (err) => this._fail(err.message));
    socket.on('close', () => this.close());

    this.handshakeTimer = setTimeout(() => {
      if (!this.ready) this._fail('handshake timed out');
    }, HANDSHAKE_TIMEOUT_MS);

    this._sendPlain({ t: 'hello', card: ctx.cardCode, nonce: this.myNonce });
  }

  // --- framing ------------------------------------------------------------

  _write(tag, body) {
    if (this.closed || this.socket.destroyed) return false;
    const header = Buffer.alloc(5);
    header.writeUInt32BE(body.length + 1, 0);
    header.writeUInt8(tag, 4);
    try {
      this.socket.write(Buffer.concat([header, body]));
      return true;
    } catch {
      return false;
    }
  }

  _sendPlain(value) {
    return this._write(TAG_PLAIN, Buffer.from(JSON.stringify(value), 'utf8'));
  }

  /** Send an application message. Only valid once the channel is up. */
  send(value) {
    if (!this.ready || !this.channelKey) return false;
    return this._write(TAG_SEALED, c.seal(this.channelKey, value));
  }

  _onData(chunk) {
    this.lastSeen = Date.now();
    this.buffer = Buffer.concat([this.buffer, chunk]);

    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);

      if (length > MAX_FRAME || length < 1) {
        return this._fail('peer sent a malformed frame');
      }
      if (this.buffer.length < 4 + length) break;

      const tag = this.buffer.readUInt8(4);
      const body = this.buffer.subarray(5, 4 + length);
      this.buffer = this.buffer.subarray(4 + length);

      try {
        if (tag === TAG_PLAIN) {
          this._onHandshake(JSON.parse(body.toString('utf8')));
        } else if (tag === TAG_SEALED) {
          if (!this.channelKey) return this._fail('sealed frame before handshake');
          this._onMessage(c.open(this.channelKey, body));
        } else {
          return this._fail(`unknown frame tag ${tag}`);
        }
      } catch (err) {
        return this._fail(err.message);
      }
    }
  }

  // --- handshake ----------------------------------------------------------

  _onHandshake(frame) {
    if (frame.t === 'hello') {
      if (this.peer) return this._fail('peer said hello twice');

      const parsed = card.parse(frame.card);

      if (this.expectId && parsed.id !== this.expectId) {
        return this._fail(`expected ${this.expectId} but reached ${parsed.id}`);
      }
      if (parsed.id === this.ctx.identity.id) {
        return this._fail('that is your own address');
      }

      this.peer = parsed;
      this.channelKey = c.deriveChannelKey(this.ctx.keys.boxPrivate, parsed.box);

      this._sendPlain({
        t: 'proof',
        sig: c.sign(this.ctx.keys.signPrivate, frame.nonce),
      });
      this.weProved = true;
      this._maybeReady();
      return;
    }

    if (frame.t === 'proof') {
      if (!this.peer) return this._fail('proof arrived before hello');
      if (!c.verify(this.peer.sign, this.myNonce, frame.sig)) {
        return this._fail('peer could not prove it owns that ID');
      }
      this.theyProved = true;
      this._maybeReady();
      return;
    }

    this._fail(`unexpected handshake frame ${frame.t}`);
  }

  _maybeReady() {
    if (this.ready || !this.theyProved || !this.weProved) return;

    this.ready = true;
    clearTimeout(this.handshakeTimer);

    this.pingTimer = setInterval(() => {
      if (Date.now() - this.lastSeen > PING_TIMEOUT_MS) return this._fail('peer went silent');
      this.send({ t: 'ping' });
    }, PING_INTERVAL_MS);

    this.emit('ready', this.peer);
  }

  // --- application messages ----------------------------------------------

  _onMessage(frame) {
    if (!this.ready) return;
    if (frame.t === 'ping') return void this.send({ t: 'pong' });
    if (frame.t === 'pong') return;
    this.emit('message', frame);
  }

  // --- teardown -----------------------------------------------------------

  _fail(reason) {
    if (this.closed) return;
    this.emit('failed', reason);
    this.close(reason);
  }

  close(reason = null) {
    if (this.closed) return;
    this.closed = true;
    this.ready = false;

    clearTimeout(this.handshakeTimer);
    clearInterval(this.pingTimer);

    try {
      this.socket.destroy();
    } catch {
      /* already gone */
    }

    this.emit('close', reason);
    this.removeAllListeners();
  }

  get remoteAddress() {
    return this.socket.remoteAddress || null;
  }
}

/**
 * Listen for friends dialling in. Resolves once the port is actually bound, or
 * rejects if it's taken so the caller can try the next one.
 *
 * `getCtx` is a function rather than a value because our own contact card is
 * rebuilt whenever the profile or external address changes, and each incoming
 * connection must be greeted with the current one.
 */
function listen(port, getCtx, onLink) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      onLink(new Link(socket, getCtx()));
    });

    server.once('error', reject);
    // '::' binds dual-stack: one socket accepts both IPv6 and IPv4 peers. IPv6
    // is the path that actually works without NAT, so it must not be optional.
    server.listen(port, '::', () => {
      server.removeListener('error', reject);
      resolve(server);
    });
  });
}

/**
 * Run the handshake over an already-connected stream.
 *
 * Split out of `dial` because a punched UDP session arrives already open —
 * there is no connect step to wait for — and because `Link` is deliberately
 * symmetric: both ends send `hello` and both answer with `proof`, so neither
 * has to be designated the caller. That is what lets two peers who dialled each
 * other simultaneously end up with one working channel instead of a deadlock.
 */
function overStream(stream, ctx, expectId = null, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    let settled = false;

    const fail = (reason, code) => {
      if (settled) return;
      settled = true;
      try {
        stream.destroy();
      } catch {
        /* already gone */
      }
      const error = new Error(reason);
      error.code = code || 'EHANDSHAKE';
      reject(error);
    };

    const timer = setTimeout(() => fail(`handshake stalled after ${timeoutMs}ms`, 'ETIMEDOUT'), timeoutMs);
    const link = new Link(stream, ctx, { expectId });

    link.once('ready', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(link);
    });

    link.once('failed', (reason) => {
      clearTimeout(timer);
      fail(reason, 'EHANDSHAKE');
    });
  });
}

/**
 * Dial a friend directly. Resolves only once the handshake has completed and
 * the peer has proven its identity, so a resolved Link is always trustworthy.
 */
function dial(host, port, ctx, expectId, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let settled = false;

    // Carry the OS error code through. Which one it is says a great deal:
    // a refusal means the packets arrived, a timeout means they vanished.
    const fail = (reason, code) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
      const error = new Error(reason);
      error.code = code || 'EFAIL';
      reject(error);
    };

    const timer = setTimeout(
      () => fail(`no reply within ${timeoutMs}ms`, 'ETIMEDOUT'),
      timeoutMs
    );

    socket.once('error', (err) => fail(err.message, err.code));

    socket.once('connect', () => {
      const link = new Link(socket, ctx, { expectId });

      link.once('ready', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(link);
      });

      link.once('failed', (reason) => {
        clearTimeout(timer);
        fail(reason, 'EHANDSHAKE');
      });
    });
  });
}

/**
 * TCP simultaneous open, for carriers that pass TCP but filter UDP.
 *
 * Same idea as the UDP punch — both ends send from their own port to the other's
 * so the two flows mirror — but TCP forces one extra constraint. Windows will
 * not let an outbound socket bind a port a listener already holds (verified:
 * EADDRINUSE even with SO_REUSEADDR), so this cannot reuse the app's port and
 * needs one of its own.
 *
 * Nothing listens on that port, on either side. That sounds broken and is in
 * fact the mechanism: two sockets that are both in SYN_SENT toward each other
 * complete the handshake between themselves, with no listening socket involved
 * anywhere. It is the one TCP state transition that needs no server.
 *
 * The port is derived rather than exchanged, so contact cards do not change: the
 * peer already knows our app port, and offsetting it lands clear of both the
 * multi-instance range and the discovery port.
 *
 * The two failure modes behave very differently, and only one of them matters:
 *
 *   - On a path that DROPS packets — the carrier firewall this exists for — the
 *     socket sits in SYN_SENT for the whole window while Windows retransmits.
 *     Both ends parked in SYN_SENT toward each other is exactly the state that
 *     completes, so the single long attempt is the one that works.
 *   - On a path that REFUSES, an RST comes back in microseconds and tears the
 *     socket down before the peer's SYN can meet it. Retrying helps a little,
 *     but a refusing path means nothing is blocking us in the first place and
 *     the ordinary dial would already have succeeded.
 *
 * So this is untestable over loopback, where every SYN to a closed port is
 * refused instantly. Its target is the case where the network stays silent.
 */
function simultaneousOpen(host, port, localPort, ctx, expectId, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    let settled = false;
    let socket = null;
    let retry = null;
    let lastCode = 'ETIMEDOUT';

    // The deadline needs its own timer, not just a check on each retry. On the
    // path this is built for the socket sits in SYN_SENT without ever erroring,
    // so a retry-driven check would never run and the caller would be held for
    // however long the OS takes to give up — about 21s on Windows.
    const overall = setTimeout(() => fail(), timeoutMs);

    const cleanup = () => {
      clearTimeout(retry);
      if (socket) {
        try {
          socket.destroy();
        } catch {
          /* already gone */
        }
        socket = null;
      }
    };

    const fail = () => {
      if (settled) return;
      settled = true;
      clearTimeout(overall);
      cleanup();
      const error = new Error(`simultaneous open did not complete (last: ${lastCode})`);
      error.code = lastCode === 'EADDRINUSE' ? 'EADDRINUSE' : 'EPUNCHFAIL';
      reject(error);
    };

    const attempt = () => {
      if (settled) return;
      if (Date.now() >= deadline) return fail();

      cleanup();
      socket = net.createConnection({ host, port, localPort, localAddress: '::' });

      socket.once('error', (err) => {
        lastCode = err.code || 'EFAIL';
        // A port we cannot bind will never become bindable inside this window.
        if (lastCode === 'EADDRINUSE') return fail();
        // Jittered, so two peers retrying in lockstep don't stay in lockstep
        // and miss each other the same way every time.
        retry = setTimeout(attempt, 300 + Math.floor(Math.random() * 400));
      });

      socket.once('connect', () => {
        if (settled) return;
        settled = true;
        clearTimeout(retry);
        clearTimeout(overall);

        const live = socket;
        socket = null;

        const link = new Link(live, ctx, { expectId });
        const remaining = Math.max(3000, deadline - Date.now());
        const handshake = setTimeout(() => {
          link.close();
          const error = new Error('connected but the handshake stalled');
          error.code = 'ETIMEDOUT';
          reject(error);
        }, remaining);

        link.once('ready', () => {
          clearTimeout(handshake);
          resolve(link);
        });
        link.once('failed', (reason) => {
          clearTimeout(handshake);
          const error = new Error(reason);
          error.code = 'EHANDSHAKE';
          reject(error);
        });
      });
    };

    attempt();
  });
}

module.exports = { Link, listen, dial, overStream, simultaneousOpen };
