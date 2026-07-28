'use strict';

/**
 * The engine. Owns the friend list, keeps links to everyone alive, and moves
 * messages between the UI and the wire.
 *
 * Every connection is an onion service. There is no second path and no fallback,
 * which is the point: the traversal machinery this replaced — port mapping,
 * firewall pinholes, hole punching, alternate ports, simultaneous open — existed
 * only to make an inbound connection possible, and every one of them could still
 * be defeated by a carrier that simply drops unsolicited packets. Tor never needs
 * one. It makes outbound connections at both ends and meets in the middle, and
 * outbound is the one thing every network on earth permits.
 *
 * The consequence worth stating plainly: no IP address is ever published,
 * announced or dialled. A friend knows your onion address and nothing else, and
 * an onion address is a public key rather than a location. That is not a mode
 * that can be switched off — it is the only thing the code can do.
 *
 * Connections are symmetric: either side may dial the other, and whoever gets
 * there first wins. A peer that dials in and proves its identity is accepted
 * automatically, because the only way it could know your address is that you
 * handed it your contact card. One person pasting a code forms the friendship.
 */

const path = require('path');
const { EventEmitter } = require('events');

const c = require('./crypto');
const card = require('./card');
const identity = require('./identity');
const store = require('./store');
const tor = require('./tor');
const transport = require('./transport');

/**
 * The port friends dial on the onion. Virtual — it exists only inside Tor, so it
 * never has to be free on this machine and is the same for everybody.
 */
const ONION_PORT = 47777;

const REDIAL_INTERVAL_MS = 30000;
const MAX_BACKOFF_MS = 300000;
const DIAL_STAGGER_MS = 2000;

/**
 * Circuits are slow to build and slower to fail. A timeout tight enough for TCP
 * would abandon connections that were about to succeed.
 */
const DIAL_TIMEOUT_MS = 90000;

/** Turn a failed dial into something a human can act on. */
function explainDialFailure(endpoint, error) {
  const where = `${endpoint.host}:${endpoint.port}`;

  switch (error.code) {
    case 'ENOTOR':
      return `${where} — tor is not running here, so nothing can be dialled.`;
    case 'ETIMEDOUT':
      return `${where} — no answer. they are probably offline, or their tor has not published yet.`;
    case 'EHANDSHAKE':
      return `${where} — reached them, but the handshake failed: ${error.message}`;
    default:
      // Tor reports "host unreachable" for a service that is not running, which
      // is the ordinary case of a friend having the app closed.
      if (/offline|unreachable/i.test(error.message)) {
        return `${where} — their meshchat is not running.`;
      }
      return `${where} — ${error.message}`;
  }
}

class Mesh extends EventEmitter {
  constructor() {
    super();
    this.friends = new Map();
    this.links = new Map();
    this.dialing = new Set();
    this.attempts = new Map();
    this.nextTry = new Map();
    this.lastFailure = new Map();

    this.server = null;
    this.tor = null;
    this.onion = null;
    this.published = false;
    this.port = null;
    this.cardCode = null;
    this.redialTimer = null;
  }

  log(text) {
    this.emit('log', text);
  }

  // --- lifecycle ----------------------------------------------------------

  async start() {
    for (const friend of store.readFriends()) this.friends.set(friend.id, friend);

    // Bound to loopback deliberately. The only thing that should ever connect
    // here is our own Tor, forwarding from the onion service; listening on a
    // real interface would accept direct connections and hand out exactly the
    // address this design exists to keep private.
    this.server = await transport.listen(0, '127.0.0.1', () => this._context(), (link) =>
      this._onInbound(link)
    );
    this.port = this.server.address().port;

    await this._startTor();

    this.redialTimer = setInterval(() => this._redialAll(), REDIAL_INTERVAL_MS);
    this._redialAll();
  }

  /**
   * Bring up Tor and publish the onion service.
   *
   * Fatal on failure, and deliberately so. There is nothing to fall back to —
   * falling back would mean connecting over a plain IP, which is the one thing
   * this app promises never to do.
   */
  async _startTor() {
    this.tor = new tor.Tor({
      dataDir: path.join(store.root, 'tor'),
      onionKey: store.readSettings().onionKey || null,
    });
    this.tor.on('log', (m) => this.log(m));

    try {
      await this.tor.start();
    } catch (err) {
      this.tor = null;
      if (err.code === 'ENOTOR') {
        for (const row of err.hint || []) this.log(row);
        throw new Error('tor is not installed — run "npm install" or see the lines above');
      }
      throw err;
    }

    const { address, key, published } = await this.tor.publish(this.port, ONION_PORT);
    this.onion = address;
    this.published = published;

    // The address is derived from this key. Lose it and every friend's copy of
    // your card points at a service that no longer exists.
    if (key) store.writeSettings({ onionKey: key });

    this._rebuildCard();
    this.emit('ready', this.status());

    if (!published) {
      this.log('tor: the descriptor is still propagating — friends may need a minute');
    }
  }

  async stop() {
    clearInterval(this.redialTimer);
    for (const link of this.links.values()) link.close();
    this.links.clear();
    if (this.server) this.server.close();
    if (this.tor) this.tor.stop();
    store.flush();
  }

  // --- identity and card --------------------------------------------------

  _context() {
    return {
      identity: identity.profile(),
      keys: identity.getKeys(),
      cardCode: this.cardCode,
    };
  }

  /**
   * Where friends reach us. Exactly one address, and it is not a location.
   *
   * Nothing else is ever added here. This function being this short is the whole
   * privacy guarantee — there is no branch that could leak an IP because there is
   * no IP in the program to leak.
   */
  _localEndpoints() {
    return this.onion ? [{ type: 'onion', host: this.onion, port: ONION_PORT }] : [];
  }

  _rebuildCard() {
    this.cardCode = card.create(identity.profile(), identity.getKeys(), this._localEndpoints());
    return this.cardCode;
  }

  myCard() {
    return this._rebuildCard();
  }

  setProfile(patch) {
    const profile = identity.setProfile(patch);
    this._rebuildCard();
    for (const link of this.links.values()) {
      link.send({ t: 'profile', name: profile.name, sigil: profile.sigil });
    }
    return profile;
  }

  status() {
    return {
      onion: this.onion,
      port: ONION_PORT,
      published: this.published,
      running: Boolean(this.tor?.ready),
      binary: tor.find(),
      friends: this.friends.size,
      online: this.links.size,
    };
  }

  // --- friends ------------------------------------------------------------

  _saveFriends() {
    store.writeFriends([...this.friends.values()]);
    this.emit('friends-changed');
  }

  /** Keep only onion endpoints, newest first, and never more than a handful. */
  _mergeEndpoints(friend, endpoints) {
    const seen = new Set();
    const merged = [];

    for (const e of [...endpoints, ...(friend.endpoints || [])]) {
      if (!e || !e.host || !tor.isOnion(e.host)) continue;
      const key = `${e.host}:${e.port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push({ type: 'onion', host: e.host, port: Number(e.port) || ONION_PORT });
    }

    friend.endpoints = merged.slice(0, 4);
  }

  _upsertFriend(peer) {
    let friend = this.friends.get(peer.id);
    const isNew = !friend;

    if (isNew) {
      friend = { id: peer.id, addedAt: Date.now(), endpoints: [] };
      this.friends.set(peer.id, friend);
    }

    friend.name = peer.name;
    friend.sigil = peer.sigil;
    friend.sign = peer.sign;
    friend.box = peer.box;
    this._mergeEndpoints(friend, peer.endpoints || []);

    this._saveFriends();
    return { friend, isNew };
  }

  /** Add someone from a pasted contact code. */
  async addFriend(input) {
    const text = String(input || '').trim();

    if (!text.startsWith(card.PREFIX)) {
      throw new Error(`paste their full ${card.PREFIX}… code`);
    }

    const peer = card.parse(text);
    if (peer.id === identity.get().id) throw new Error('that is your own code');

    if (!(peer.endpoints || []).some((e) => tor.isOnion(e.host))) {
      throw new Error('that code has no onion address — they need to send a new one');
    }

    const { friend, isNew } = this._upsertFriend(peer);
    this.log(`${isNew ? 'added' : 'updated'} ${friend.name} ${friend.id}`);
    this._connect(friend).catch(() => {});
    return friend;
  }

  removeFriend(id) {
    const link = this.links.get(id);
    if (link) link.close();
    const existed = this.friends.delete(id);
    if (existed) this._saveFriends();
    return existed;
  }

  /** Look someone up by Mesh ID, a unique ID fragment, or display name. */
  resolve(query) {
    const q = String(query || '').trim();
    if (!q) return null;

    const upper = q.toUpperCase();
    if (this.friends.has(upper)) return this.friends.get(upper);

    const matches = [...this.friends.values()].filter(
      (f) =>
        f.id.replace(/-/g, '').includes(upper.replace(/-/g, '')) ||
        f.name.toLowerCase() === q.toLowerCase()
    );

    return matches.length === 1 ? matches[0] : null;
  }

  list() {
    return [...this.friends.values()].map((f) => ({
      id: f.id,
      name: f.name,
      sigil: f.sigil,
      online: this.links.has(f.id),
      endpoints: f.endpoints || [],
    }));
  }

  // --- connections --------------------------------------------------------

  _onInbound(link) {
    // Nothing is recorded about where an inbound peer came from. Over Tor the
    // remote address is always 127.0.0.1 — it is our own Tor handing the
    // connection over — so there is nothing true to learn, and asking would be
    // pointless as well as unwanted.
    link.once('ready', () => this._adopt(link));
    link.once('failed', (reason) => this.log(`rejected inbound link: ${reason}`));
  }

  _adopt(link) {
    const peer = link.peer;

    if (this.links.has(peer.id)) {
      // Both sides dialled at once; keep the connection we already trust.
      link.close();
      return;
    }

    const { friend, isNew } = this._upsertFriend(peer);
    this.links.set(peer.id, link);
    this.attempts.delete(peer.id);
    this.nextTry.delete(peer.id);
    this.lastFailure.delete(peer.id);

    if (isNew) this.log(`new peer accepted: ${friend.name} ${friend.id}`);
    this.log(`connected to ${friend.name}`);
    this.emit('status', { id: peer.id, name: friend.name, online: true });

    link.on('message', (frame) => this._onFrame(peer.id, frame));
    link.on('close', () => {
      if (this.links.get(peer.id) !== link) return;
      this.links.delete(peer.id);
      this.log(`lost ${friend.name}`);
      this.emit('status', { id: peer.id, name: friend.name, online: false });
    });

    link.send({ t: 'endpoint', endpoints: this._localEndpoints() });
    this._flushOutbox(peer.id);
  }

  /** Dial one onion endpoint and complete the handshake inside the circuit. */
  _dialEndpoint(endpoint, expectId) {
    if (!this.tor?.ready) {
      const error = new Error('tor is not running');
      error.code = 'ENOTOR';
      return Promise.reject(error);
    }

    return this.tor
      .dial(endpoint.host, endpoint.port, DIAL_TIMEOUT_MS)
      .then((socket) =>
        transport.overStream(socket, this._context(), expectId, DIAL_TIMEOUT_MS)
      );
  }

  async _connect(friend, { verbose = false } = {}) {
    if (this.links.has(friend.id) || this.dialing.has(friend.id)) return null;

    const endpoints = this._orderEndpoints(friend.endpoints);
    if (!endpoints.length) {
      if (verbose) this.log(`${friend.name} has no onion address on record`);
      return { ok: false, reasons: ['their card has no onion address'] };
    }

    const failures = [];
    this.dialing.add(friend.id);
    try {
      const link = await this._race(endpoints, friend.id, (endpoint, error) =>
        failures.push(explainDialFailure(endpoint, error))
      );

      if (link) {
        this._adopt(link);
        return { ok: true, reasons: [] };
      }
    } finally {
      this.dialing.delete(friend.id);
    }

    this._backOff(friend.id);
    this._reportFailure(friend, failures, verbose);
    return { ok: false, reasons: failures };
  }

  /**
   * Say why a friend is unreachable, but only when the reason changes —
   * otherwise a permanently offline friend would spam the log forever.
   */
  _reportFailure(friend, failures, verbose) {
    const signature = failures.join('|');
    if (!verbose && this.lastFailure.get(friend.id) === signature) return;
    this.lastFailure.set(friend.id, signature);

    this.log(`could not reach ${friend.name}:`);
    for (const reason of failures) this.log(`  ${reason}`);
  }

  /** Force an immediate attempt and report everything, for /try. */
  async probe(friendId) {
    const friend = this.friends.get(friendId);
    if (!friend) throw new Error('not a friend');
    if (this.links.has(friendId)) {
      return { ok: true, alreadyOnline: true, endpoints: friend.endpoints || [], reasons: [] };
    }

    this.attempts.delete(friendId);
    this.nextTry.delete(friendId);
    this.lastFailure.delete(friendId);

    const result = (await this._connect(friend, { verbose: true })) || {
      ok: false,
      reasons: ['a connection attempt is already in progress'],
    };

    return { ...result, endpoints: this._orderEndpoints(friend.endpoints) };
  }

  /**
   * Try each known address, staggered. Friends almost always have exactly one,
   * so this matters only just after somebody's address has changed and both the
   * old and new are on record.
   */
  _race(endpoints, expectId, onFailure = () => {}) {
    return new Promise((resolve) => {
      let settled = false;
      let pending = endpoints.length;
      const timers = [];

      const finish = (link) => {
        if (settled) {
          if (link) link.close();
          return;
        }
        settled = true;
        for (const timer of timers) clearTimeout(timer);
        resolve(link);
      };

      const oneDone = () => {
        if (--pending === 0) finish(null);
      };

      endpoints.forEach((endpoint, index) => {
        timers.push(
          setTimeout(() => {
            if (settled) return oneDone();
            this._dialEndpoint(endpoint, expectId)
              .then((link) => finish(link))
              .catch((error) => onFailure(endpoint, error))
              .finally(oneDone);
          }, index * DIAL_STAGGER_MS)
        );
      });
    });
  }

  /** Onion addresses only, and never our own. */
  _orderEndpoints(endpoints = []) {
    return (endpoints || []).filter((e) => tor.isOnion(e.host) && e.host !== this.onion);
  }

  _backOff(id) {
    const attempts = (this.attempts.get(id) || 0) + 1;
    this.attempts.set(id, attempts);
    const delay = Math.min(MAX_BACKOFF_MS, 15000 * 2 ** (attempts - 1));
    this.nextTry.set(id, Date.now() + delay);
  }

  _redialAll() {
    const now = Date.now();
    for (const friend of this.friends.values()) {
      if (this.links.has(friend.id) || this.dialing.has(friend.id)) continue;
      if ((this.nextTry.get(friend.id) || 0) > now) continue;
      if (!friend.endpoints?.length) continue;
      this._connect(friend).catch(() => {});
    }
  }

  // --- messages -----------------------------------------------------------

  _onFrame(peerId, frame) {
    const friend = this.friends.get(peerId);
    if (!friend) return;

    if (frame.t === 'msg') {
      const message = {
        id: String(frame.id || c.messageId()),
        ts: Number(frame.ts) || Date.now(),
        body: String(frame.body || '').slice(0, 4000),
        mine: false,
        state: 'received',
      };
      store.appendMessage(peerId, message);
      const link = this.links.get(peerId);
      if (link) link.send({ t: 'ack', id: message.id });
      this.emit('message', { peerId, name: friend.name, message });
      return;
    }

    if (frame.t === 'ack') {
      const updated = store.updateMessage(peerId, String(frame.id), { state: 'delivered' });
      if (updated) this.emit('delivered', { peerId, id: updated.id });
      return;
    }

    if (frame.t === 'profile') {
      friend.name = String(frame.name || friend.name).slice(0, 24);
      friend.sigil = String(frame.sigil || friend.sigil).slice(0, 2);
      this._saveFriends();
      return;
    }

    if (frame.t === 'endpoint') {
      // Only onion addresses survive the merge, so a peer that sent an IP —
      // whether an old build or a hostile one — cannot get us to dial it.
      this._mergeEndpoints(friend, Array.isArray(frame.endpoints) ? frame.endpoints : []);
      this._saveFriends();
    }
  }

  sendText(peerId, body) {
    const friend = this.friends.get(peerId);
    if (!friend) throw new Error('not a friend');

    const message = {
      id: c.messageId(),
      ts: Date.now(),
      body: String(body).slice(0, 4000),
      mine: true,
      state: 'queued',
    };
    store.appendMessage(peerId, message);

    const link = this.links.get(peerId);
    if (link && link.send({ t: 'msg', id: message.id, ts: message.ts, body: message.body })) {
      store.updateMessage(peerId, message.id, { state: 'sent' });
      message.state = 'sent';
    }

    return message;
  }

  /** Hand over anything composed while the friend was offline. */
  _flushOutbox(peerId) {
    const link = this.links.get(peerId);
    if (!link) return;

    const pending = store.undelivered(peerId);
    if (!pending.length) return;

    for (const message of pending) {
      if (link.send({ t: 'msg', id: message.id, ts: message.ts, body: message.body })) {
        store.updateMessage(peerId, message.id, { state: 'sent' });
      }
    }
    this.log(`flushed ${pending.length} queued message(s)`);
    this.emit('history-changed', { peerId });
  }

  history(peerId, limit = 60) {
    return store.recentMessages(peerId, limit);
  }
}

module.exports = { Mesh, ONION_PORT };
