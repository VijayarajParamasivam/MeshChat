'use strict';

/**
 * The wire: a mutual-proof handshake and an encrypted channel, carried inside a
 * Tor circuit.
 *
 * Nothing here knows that. It is handed a stream and speaks the same protocol it
 * would over a LAN cable, which is the point — the encryption below does not
 * depend on the transport keeping any promises, and the transport is not trusted
 * to. A relay carrying these bytes sees what an eavesdropper on a LAN sees.
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
/**
 * Generous because every round trip crosses six relays. Two exchanges that cost
 * microseconds on a LAN cost seconds here, and cutting them off early would
 * abandon handshakes that were about to succeed.
 */
const HANDSHAKE_TIMEOUT_MS = 45000;
const PING_INTERVAL_MS = 20000;
const PING_TIMEOUT_MS = 60000;

/**
 * What a proof actually signs.
 *
 * Signing the bare nonce made the signature a free-floating assertion that said
 * nothing about who produced it or who it was for — valid in any context that
 * happened to present the same bytes. Naming the protocol, the signer and the
 * intended recipient makes it answer exactly one question: "did this identity
 * prove itself to that identity, in this handshake?"
 */
const PROOF_CONTEXT = 'torchat-proof-v1';

function proofPayload(nonce, signerId, recipientId) {
  return `${PROOF_CONTEXT}|${nonce}|${signerId}|${recipientId}`;
}

class Link extends EventEmitter {
  /**
   * @param {net.Socket} socket
   * @param {object} ctx      { identity, keys, cardCode }
   * @param {object} options  { expectId } when we dialled a specific friend,
   *                          { handshakeTimeoutMs } to match the caller's budget
   */
  constructor(
    socket,
    ctx,
    { expectId = null, handshakeTimeoutMs = HANDSHAKE_TIMEOUT_MS, greetFirst = true } = {}
  ) {
    super();
    this.socket = socket;
    this.ctx = ctx;
    this.expectId = expectId;

    this.peer = null;
    this.ready = false;
    this.closed = false;
    this.greeted = false;

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
    }, handshakeTimeoutMs);

    // Only the side that dialled may speak first. See _sendHello.
    if (greetFirst) this._sendHello();
  }

  /**
   * Send our opening frame, exactly once.
   *
   * The side that *accepted* the connection must not send this until the dialler
   * has been heard from, and that is not a style preference — it is a hard
   * property of the transport. Tor discards anything an onion service writes
   * into a rendezvous stream before the CONNECTED cell reaches the other end,
   * silently and with no error on the writing side. Measured: a 120-byte marker
   * written on accept never arrived, while the same marker written four seconds
   * later arrived in 380ms.
   *
   * The old code greeted from the constructor on both sides, so the responder's
   * hello was destroyed every single time. What survived was its `proof`, sent
   * afterwards in reply to the dialler's hello — which is why every connection
   * over Tor died with "proof arrived before hello". The handshake is still
   * symmetric in content; only the responder's timing has changed.
   */
  _sendHello() {
    if (this.greeted) return;
    this.greeted = true;
    this._sendPlain({ t: 'hello', card: this.ctx.cardCode, nonce: this.myNonce });
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

      // A nonce we never validated was signed as the string "undefined", which
      // is the same challenge for every peer that omits it — the one input to
      // the proof that must not be attacker-chosen or constant.
      if (typeof frame.nonce !== 'string' || frame.nonce.length < 16) {
        return this._fail('peer sent no usable challenge');
      }

      const parsed = card.parse(frame.card);

      if (this.expectId && parsed.id !== this.expectId) {
        return this._fail(`expected ${this.expectId} but reached ${parsed.id}`);
      }
      if (parsed.id === this.ctx.identity.id) {
        return this._fail('that is your own address');
      }

      this.peer = parsed;
      this.channelKey = c.deriveChannelKey(this.ctx.keys.boxPrivate, parsed.box);

      // Now it is safe to speak: hearing from them proves the stream is joined
      // end to end, so this will actually be delivered. Hello before proof —
      // they cannot check a proof from someone who has not identified themselves.
      this._sendHello();

      this._sendPlain({
        t: 'proof',
        sig: c.sign(
          this.ctx.keys.signPrivate,
          proofPayload(frame.nonce, this.ctx.identity.id, parsed.id)
        ),
      });
      this.weProved = true;
      this._maybeReady();
      return;
    }

    if (frame.t === 'proof') {
      if (!this.peer) return this._fail('proof arrived before hello');
      const expected = proofPayload(this.myNonce, this.peer.id, this.ctx.identity.id);
      if (!c.verify(this.peer.sign, expected, frame.sig)) {
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
function listen(port, host, getCtx, onLink) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      // greetFirst: false — we accepted, so we wait to be spoken to. Greeting
      // here would write into a rendezvous stream Tor has not finished joining,
      // and the frame would be dropped without a word. See Link._sendHello.
      onLink(new Link(socket, getCtx(), { greetFirst: false }));
    });

    server.once('error', reject);
    // The host is explicit and, in practice, always loopback: the only thing
    // that connects here is our own Tor forwarding from the onion service.
    // Binding a real interface would accept direct connections and give away
    // the address the onion exists to keep private.
    server.listen(port, host, () => {
      server.removeListener('error', reject);

      // Something must stay attached. A server error after bind — EMFILE under
      // load is the realistic one — is an unheard 'error' event, and an unheard
      // 'error' event takes the whole process down rather than logging.
      server.on('error', (err) => server.emit('listen-error', err));

      resolve(server);
    });
  });
}

/**
 * Run the handshake over an already-connected stream.
 *
 * A Tor circuit arrives already open — there is no connect step to wait for.
 * `Link` stays symmetric in content: both ends send `hello` and both answer with
 * `proof`, so two peers who dialled each other at once still end up with one
 * working channel rather than a deadlock. Only the ordering is asymmetric, and
 * only because Tor forces it: the dialler speaks first, and the side that
 * accepted answers. See Link._sendHello for why.
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

    // The Link gets the caller's budget too. With its own fixed 45s it always
    // fired first over Tor, so a caller asking for 90s silently got 45 and a
    // handshake that was merely slow across six relays was reported as failed.
    const link = new Link(stream, ctx, { expectId, handshakeTimeoutMs: timeoutMs });

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

module.exports = { Link, listen, overStream };
