'use strict';

/**
 * UDP hole punching: the path that works when *neither* peer can be dialled.
 *
 * A stateful firewall does not block inbound packets, it blocks packets that
 * belong to no conversation. The state it keeps is keyed on the whole tuple —
 * both addresses and both ports — so when we dial out from a random ephemeral
 * port we open a pinhole for traffic coming back to *that* port, and the peer
 * dialling our listening port matches nothing. Both sides punch holes, both
 * holes are in the wrong place, and both sides conclude the other is offline.
 *
 * The fix is to make the two flows mirror images of each other. If both ends
 * send from their own listening port to the other's listening port:
 *
 *     us   -> them:   [us]:47777  ->  [them]:47777
 *     them -> us:     [them]:47777 -> [us]:47777
 *
 * then each side's outbound flow is byte-for-byte the inbound flow the other
 * needs, and each firewall sees the arriving packet as the reply to something
 * its own user already sent. Nothing in the middle has to cooperate, and no
 * third party is involved: the only thing the two ends must agree on is the
 * port number, which is already in the contact card.
 *
 * The catch is timing. A pinhole opened by an outbound packet lives for tens of
 * seconds, so both sides have to be punching at roughly the same moment. With
 * no server to coordinate through, they align on the wall clock instead — see
 * `msUntilWindow`.
 *
 * UDP rather than TCP on purpose. The technique works for both, but carrier
 * firewalls treat a bare SYN arriving from an unexpected direction far more
 * harshly than a UDP datagram, and Windows makes binding an already-listening
 * port for outbound TCP awkward. The cost is that UDP gives us no ordering or
 * retransmission, so this file provides them.
 *
 * Nothing here is authenticated. It does not need to be: anyone who guesses the
 * tuple can get datagrams delivered, but the Link handshake layered on top still
 * demands an Ed25519 signature over a fresh nonce before a single message flows.
 * An unauthenticated punch buys an attacker the right to fail a handshake, which
 * is exactly what it buys them over TCP.
 */

const dgram = require('dgram');
const { EventEmitter } = require('events');

const PUNCH = 0x01;
const PUNCH_ACK = 0x02;
const DATA = 0x03;
const ACK = 0x04;
const CLOSE = 0x05;

/**
 * IPv6 guarantees 1280 bytes end to end. Minus a 40-byte IPv6 header, an 8-byte
 * UDP header and our own 5-byte DATA header, 1200 leaves comfortable room and
 * never relies on fragmentation, which many firewalls drop outright.
 */
const MAX_PAYLOAD = 1200;

const PUNCH_INTERVAL_MS = 500;
const RETRANSMIT_MS = 600;
const RETRANSMIT_CHECK_MS = 200;
const MAX_RETRIES = 12;
const KEEPALIVE_MS = 15000;
const IDLE_TIMEOUT_MS = 60000;
const SEND_WINDOW = 32;
const MAX_HELD_FRAMES = 256;
const MAX_SESSIONS = 64;

/**
 * How long a punch attempt keeps firing. Longer than the worst plausible clock
 * skew between two machines that have never spoken to each other.
 */
const PUNCH_WINDOW_MS = 10000;

/**
 * Both sides must be punching at once, and they have no channel to agree on
 * "now" through. The wall clock is the one reference they already share: align
 * every attempt to a fixed period since the epoch and two machines whose clocks
 * agree to within a few seconds will always overlap.
 *
 * The period is deliberately longer than the window so an attempt finishes
 * before the next one is due.
 */
const PUNCH_PERIOD_MS = 30000;

/**
 * How often a "warm" peer gets a lone datagram to hold its pinhole open.
 *
 * Comfortably inside the shortest firewall UDP timeout worth worrying about
 * (conntrack commonly expires unanswered UDP flows at 30s).
 */
const WARM_INTERVAL_MS = 20000;

/**
 * Ports to try alongside the app's own, for carriers that filter by port rather
 * than wholesale.
 *
 * 443 is QUIC and 53 is DNS. Both carry so much ordinary traffic that blocking
 * them breaks the web, so they tend to survive filtering that kills a high
 * random port. Neither side needs to advertise these: both derive the same list,
 * bind the same ports, and send from each to the same one on the other end, so
 * reciprocity holds without anything extra in the contact card.
 *
 * Binding them is best-effort. They are privileged on Unix and often already
 * taken, and failing to get one simply means that avenue isn't tried.
 */
const ALT_PORTS = [443, 53];

/** Milliseconds until the next punch window opens. */
function msUntilWindow(now = Date.now(), period = PUNCH_PERIOD_MS) {
  const into = now % period;
  return into === 0 ? 0 : period - into;
}

/**
 * A dual-stack socket reports an IPv4 peer as `::ffff:10.0.0.5` but will not
 * accept that same address back with a bare `10.0.0.5` in `send`. Normalising
 * both directions keeps session keys stable regardless of which form we were
 * handed.
 */
function normaliseHost(host) {
  const bare = String(host).split('%')[0];
  return /^\d+\.\d+\.\d+\.\d+$/.test(bare) ? `::ffff:${bare}` : bare;
}

/**
 * Sessions are identified by the whole flow, not just the peer.
 *
 * Reciprocity means we always send from the port we receive on, but the peer's
 * port need not match ours — a second instance listens on the next port up, and
 * the alternate-port attempts use ports of their own. Two flows to the same peer
 * from different local ports are genuinely different holes, so the local port
 * belongs in the key.
 */
function keyFor(host, port, localPort) {
  return `${localPort}|[${normaliseHost(host)}]:${port}`;
}

/**
 * The `net.Socket` surface that `Link` actually uses, backed by datagrams.
 *
 * Presenting the same shape means the handshake, framing and encryption above
 * are completely unaware they are no longer running on TCP — the transport is
 * swapped underneath them without a line changing.
 */
class UdpStream extends EventEmitter {
  constructor(hub, host, port, localPort) {
    super();
    this.hub = hub;
    this.host = normaliseHost(host);
    this.port = port;
    this.localPort = localPort;
    this.destroyed = false;

    // Outbound reliability.
    this.nextSeq = 1;
    this.unacked = new Map(); // seq -> { buf, sentAt, tries }
    this.queue = []; // chunks waiting for window space

    // Inbound reassembly.
    this.expected = 1;
    this.held = new Map(); // seq -> payload

    this.lastHeard = Date.now();

    this.timer = setInterval(() => this._tick(), RETRANSMIT_CHECK_MS);
  }

  /** TCP-only concept; the keepalive below plays the same role. */
  setKeepAlive() {}

  get remoteAddress() {
    return this.host;
  }

  write(buf) {
    if (this.destroyed) return false;

    for (let at = 0; at < buf.length; at += MAX_PAYLOAD) {
      const slice = buf.subarray(at, at + MAX_PAYLOAD);
      const seq = this.nextSeq++;
      const frame = Buffer.alloc(5 + slice.length);
      frame.writeUInt8(DATA, 0);
      frame.writeUInt32BE(seq, 1);
      slice.copy(frame, 5);
      this.queue.push({ seq, buf: frame });
    }

    this._drain();
    return this.queue.length === 0;
  }

  /** Move queued chunks onto the wire while the window has room. */
  _drain() {
    while (this.queue.length && this.unacked.size < SEND_WINDOW) {
      const chunk = this.queue.shift();
      this.unacked.set(chunk.seq, { buf: chunk.buf, sentAt: Date.now(), tries: 1 });
      this.hub._send(chunk.buf, this.host, this.port, this.localPort);
    }
  }

  _tick() {
    if (this.destroyed) return;

    const now = Date.now();

    if (now - this.lastHeard > IDLE_TIMEOUT_MS) {
      return this._error('peer went silent');
    }

    if (now - this.lastHeard > KEEPALIVE_MS && !this.unacked.size) {
      this.hub._send(Buffer.from([PUNCH]), this.host, this.port, this.localPort);
    }

    for (const [seq, entry] of this.unacked) {
      if (now - entry.sentAt < RETRANSMIT_MS) continue;

      if (entry.tries >= MAX_RETRIES) {
        return this._error(`gave up resending packet ${seq}`);
      }

      entry.tries += 1;
      entry.sentAt = now;
      this.hub._send(entry.buf, this.host, this.port, this.localPort);
    }
  }

  /** Called by the hub for every datagram arriving from this peer. */
  _receive(type, body) {
    this.lastHeard = Date.now();

    if (type === CLOSE) return this.destroy();

    if (type === ACK) {
      const through = body.readUInt32BE(0);
      for (const seq of [...this.unacked.keys()]) {
        if (seq <= through) this.unacked.delete(seq);
      }
      this._drain();
      return;
    }

    if (type !== DATA) return;

    const seq = body.readUInt32BE(0);
    const payload = body.subarray(4);

    if (seq === this.expected) {
      this.expected += 1;
      this.emit('data', payload);

      // A gap may have been filled, so release whatever is now contiguous.
      while (this.held.has(this.expected)) {
        const next = this.held.get(this.expected);
        this.held.delete(this.expected);
        this.expected += 1;
        this.emit('data', next);
      }
    } else if (seq > this.expected && this.held.size < MAX_HELD_FRAMES) {
      this.held.set(seq, payload);
    }

    // Always acknowledge, including for duplicates — a lost ACK is why the peer
    // is resending, and staying silent would keep it resending forever.
    const ack = Buffer.alloc(5);
    ack.writeUInt8(ACK, 0);
    ack.writeUInt32BE(this.expected - 1, 1);
    this.hub._send(ack, this.host, this.port, this.localPort);
  }

  _error(reason) {
    if (this.destroyed) return;
    const error = new Error(reason);
    error.code = 'EPUNCHLOST';
    this.emit('error', error);
    this.destroy();
  }

  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    clearInterval(this.timer);

    this.hub._send(Buffer.from([CLOSE]), this.host, this.port, this.localPort);
    this.hub._drop(keyFor(this.host, this.port, this.localPort));

    this.emit('close');
    this.removeAllListeners();
  }
}

/**
 * Owns the one UDP socket everything shares and routes datagrams to sessions.
 *
 * A single socket is not an optimisation — it is the entire point. Every packet
 * we send must leave from the port peers will send back to, so one bound port
 * has to serve both punching and carrying traffic for every peer at once.
 */
class Hub extends EventEmitter {
  constructor(port, altPorts = ALT_PORTS) {
    super();
    this.port = port;
    // One socket per port we punch from. Because both ends send from a port to
    // the same port number on the other, the peer's port tells us which of our
    // sockets a datagram belongs to — no extra bookkeeping needed.
    this.sockets = new Map(); // local port -> dgram socket
    this.altPorts = altPorts.filter((p) => p !== port);
    this.sessions = new Map(); // key -> UdpStream
    this.punches = new Map(); // key -> { timer, deadline, resolve, reject, done }
    this.warm = new Map(); // key -> { host, port }
    this.warmTimer = null;
  }

  /**
   * Hold a pinhole open toward a peer indefinitely.
   *
   * Windowed punching demands that both people be at their machines in the same
   * thirty seconds, which is a lot to ask. Sending one datagram every twenty
   * seconds instead means our side of the hole is *always* open, so whoever
   * comes online second is let straight through with no coordination at all.
   * The alignment machinery stays for first contact, when neither side has any
   * reason to have been warming the other.
   *
   * One small datagram per peer per twenty seconds — cheap enough to leave
   * running, which is the only reason it can be relied on.
   */
  keepWarm(host, port, fromPort = this.port) {
    if (!this.sockets.has(fromPort)) return;
    this.warm.set(keyFor(host, port, fromPort), { host, port, fromPort });

    if (!this.warmTimer) {
      this.warmTimer = setInterval(() => this._warmTick(), WARM_INTERVAL_MS);
      if (this.warmTimer.unref) this.warmTimer.unref();
    }
  }

  /** Stop holding a hole open — the peer is connected, or no longer a friend. */
  cool(host, port, fromPort = this.port) {
    this.warm.delete(keyFor(host, port, fromPort));
    if (!this.warm.size && this.warmTimer) {
      clearInterval(this.warmTimer);
      this.warmTimer = null;
    }
  }

  /** Forget every warm target, then let the caller re-add the current set. */
  coolAll() {
    this.warm.clear();
    if (this.warmTimer) {
      clearInterval(this.warmTimer);
      this.warmTimer = null;
    }
  }

  _warmTick() {
    for (const [key, target] of this.warm) {
      // A live session already keeps its own path open; sending more would be
      // pure noise.
      if (this.sessions.has(key)) continue;
      this._send(Buffer.from([PUNCH]), target.host, target.port, target.fromPort);
    }
  }

  /**
   * Bind one port. udp6 without ipv6Only also accepts IPv4 peers as ::ffff:.
   *
   * `reuseAddr` only for our own port, where it buys a clean restart without
   * waiting on the previous socket. The borrowed ports must NOT set it: on
   * Windows two UDP sockets with SO_REUSEADDR can hold the same port and split
   * the traffic between them, so we would quietly steal datagrams from whatever
   * real QUIC or DNS service was already there. Without it the bind fails, which
   * is exactly what we want — that port simply isn't ours to take.
   */
  _bind(port, { exclusive = false } = {}) {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket({ type: 'udp6', reuseAddr: !exclusive });

      socket.once('error', reject);
      socket.on('message', (msg, rinfo) => this._onMessage(msg, rinfo, port));

      socket.bind(port, () => {
        socket.removeListener('error', reject);
        socket.on('error', (err) => this.emit('log', `punch socket ${port}: ${err.message}`));
        this.sockets.set(port, socket);
        resolve(socket);
      });
    });
  }

  async start() {
    // The app's own port has to work; without it there is no punching at all.
    await this._bind(this.port);

    for (const port of this.altPorts) {
      try {
        await this._bind(port, { exclusive: true });
      } catch {
        // Privileged, taken, or otherwise unavailable. Nothing is lost beyond
        // that one extra avenue, so it is not worth reporting as an error.
      }
    }

    const extra = this.altPorts.filter((p) => this.sockets.has(p));
    if (extra.length) {
      this.emit('log', `punch: also listening on ${extra.join(', ')} for filtered networks`);
    }

    return this;
  }

  /** Every port we can punch from, the app's own first. */
  ports() {
    return [this.port, ...this.altPorts.filter((p) => this.sockets.has(p))];
  }

  stop() {
    this.coolAll();

    for (const attempt of this.punches.values()) this._settlePunch(attempt, null);
    this.punches.clear();

    for (const session of [...this.sessions.values()]) session.destroy();
    this.sessions.clear();

    for (const socket of this.sockets.values()) {
      try {
        socket.close();
      } catch {
        /* already closed */
      }
    }
    this.sockets.clear();
  }

  /**
   * The local port is explicit rather than inferred from the peer's, because the
   * two are not always equal: a second instance listens one port up, and only
   * the alternate-port attempts have both ends on the same number. What must
   * always hold is that we send from the port we receive on — that is what makes
   * our outbound flow the mirror of the peer's, and it is the whole mechanism.
   */
  _send(buf, host, port, localPort) {
    const socket = this.sockets.get(localPort);
    if (!socket) return;
    try {
      socket.send(buf, port, normaliseHost(host));
    } catch {
      /* a dead socket surfaces through the idle timeout instead */
    }
  }

  _drop(key) {
    this.sessions.delete(key);
  }

  _onMessage(msg, rinfo, localPort) {
    if (!msg.length) return;

    const key = keyFor(rinfo.address, rinfo.port, localPort);
    const type = msg.readUInt8(0);
    const body = msg.subarray(1);

    // A punch from them proves their packets reach us. Answering proves ours
    // reach them, which is the half they cannot establish on their own.
    if (type === PUNCH) {
      this._send(Buffer.from([PUNCH_ACK]), rinfo.address, rinfo.port, localPort);
      this._open(key, rinfo.address, rinfo.port, localPort);
      return;
    }

    // Their acknowledgement is the one packet that proves both directions at
    // once: it could only exist if our punch arrived, and it only reached us if
    // theirs can too.
    if (type === PUNCH_ACK) {
      this._open(key, rinfo.address, rinfo.port, localPort);
      return;
    }

    const session = this.sessions.get(key);
    if (!session) {
      // Data for a session we have torn down. Tell them so they stop resending
      // rather than retrying into a void.
      if (type !== CLOSE) this._send(Buffer.from([CLOSE]), rinfo.address, rinfo.port, localPort);
      return;
    }

    session._receive(type, body);
  }

  /**
   * Promote a peer we have proven two-way contact with into a live session.
   * Safe to call repeatedly — punches keep arriving after the first one lands.
   */
  _open(key, host, port, localPort) {
    const existing = this.sessions.get(key);
    const attempt = this.punches.get(key);

    if (existing) {
      if (attempt) this._settlePunch(attempt, existing);
      return existing;
    }

    if (this.sessions.size >= MAX_SESSIONS) return null;

    const session = new UdpStream(this, host, port, localPort);
    this.sessions.set(key, session);

    // A punch we started resolves through its promise; one that arrived out of
    // the blue is a peer reaching us first, and needs somebody to pick it up.
    // Routing both down the same path would build two Links on one stream.
    if (attempt) this._settlePunch(attempt, session);
    else this.emit('session', session);

    return session;
  }

  _settlePunch(attempt, session) {
    if (attempt.done) return;
    attempt.done = true;
    clearInterval(attempt.timer);
    clearTimeout(attempt.deadline);
    this.punches.delete(attempt.key);

    if (session) attempt.resolve(session);
    else {
      const error = new Error('punch window closed with no reply');
      error.code = 'EPUNCHFAIL';
      attempt.reject(error);
    }
  }

  /**
   * Punch a hole to a peer and resolve with a stream once packets cross.
   *
   * `aligned` waits for the shared wall-clock boundary first, which is what
   * makes both ends fire together. Pass false to punch immediately — useful when
   * something else already told us the peer is live right now, such as a LAN
   * beacon, or when a human asked for an attempt and is waiting on it.
   */
  punch(host, port, { aligned = true, windowMs = PUNCH_WINDOW_MS, fromPort = this.port } = {}) {
    const key = keyFor(host, port, fromPort);

    if (!this.sockets.has(fromPort)) {
      const error = new Error(`no socket bound on ${fromPort}`);
      error.code = 'EPUNCHFAIL';
      return Promise.reject(error);
    }

    const existing = this.sessions.get(key);
    if (existing && !existing.destroyed) return Promise.resolve(existing);

    const running = this.punches.get(key);
    if (running) return running.promise;

    const attempt = { key, done: false };
    attempt.promise = new Promise((resolve, reject) => {
      attempt.resolve = resolve;
      attempt.reject = reject;
    });

    const begin = () => {
      if (attempt.done) return;

      const fire = () => this._send(Buffer.from([PUNCH]), host, port, fromPort);
      fire();
      attempt.timer = setInterval(fire, PUNCH_INTERVAL_MS);
      attempt.deadline = setTimeout(() => this._settlePunch(attempt, null), windowMs);
    };

    this.punches.set(key, attempt);

    const wait = aligned ? msUntilWindow() : 0;
    if (wait === 0) begin();
    else {
      attempt.deadline = setTimeout(begin, wait);
      // Until the window opens the attempt owns only this timer; replacing it
      // inside begin() is deliberate.
    }

    return attempt.promise;
  }
}

module.exports = {
  Hub,
  UdpStream,
  msUntilWindow,
  normaliseHost,
  keyFor,
  PUNCH_PERIOD_MS,
  PUNCH_WINDOW_MS,
  WARM_INTERVAL_MS,
  MAX_PAYLOAD,
  types: { PUNCH, PUNCH_ACK, DATA, ACK, CLOSE },
};
