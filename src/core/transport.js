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

module.exports = { Link, listen, dial };
