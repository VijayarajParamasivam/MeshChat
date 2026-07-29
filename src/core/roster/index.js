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
 *
 * This file is the wiring. The parts it holds together each own one concern:
 * friends.js remembers who you know, dialer.js decides what to try and when,
 * messages.js owns the delivery contract.
 */

const path = require('path');
const { EventEmitter } = require('events');

const card = require('../card');
const identity = require('../identity');
const store = require('../store');
const tor = require('../tor');
const transport = require('../transport');

const { ONION_PORT, REDIAL_INTERVAL_MS, DIAL_TIMEOUT_MS } = require('./constants');
const { FriendBook } = require('./friends');
const { Messenger } = require('./messages');
const { explainDialFailure, orderEndpoints, raceEndpoints, RetryPolicy } = require('./dialer');

class TorChat extends EventEmitter {
  constructor() {
    super();

    this.links = new Map();
    this.dialing = new Set();
    this.retry = new RetryPolicy();

    this.book = new FriendBook(store, () => this.emit('friends-changed'));
    this.messenger = new Messenger({
      store,
      links: this.links,
      emit: (event, payload) => this.emit(event, payload),
      log: (text) => this.log(text),
    });

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

  /** The friend list, as a Map. Read freely; write through the book. */
  get friends() {
    return this.book.all;
  }

  // --- lifecycle ----------------------------------------------------------

  async start() {
    this.book.load();

    // Bound to loopback deliberately. The only thing that should ever connect
    // here is our own Tor, forwarding from the onion service; listening on a
    // real interface would accept direct connections and hand out exactly the
    // address this design exists to keep private.
    this.server = await transport.listen(0, '127.0.0.1', () => this._context(), (link) =>
      this._onInbound(link)
    );
    this.server.on('listen-error', (err) => this.log(`listener error: ${err.message}`));
    this.port = this.server.address().port;

    // If Tor cannot start there is nothing to listen for, and leaving the socket
    // bound would leak it for the life of the process — the caller has no handle
    // to close it, because start() never returned one.
    try {
      await this._startTor();
    } catch (err) {
      this.server.close();
      this.server = null;
      throw err;
    }

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

    // Tor dying takes every link with it. Tear them down so each friend is
    // reported offline once, rather than looking online while every send
    // silently fails.
    this.tor.on('down', () => {
      this.published = false;
      for (const link of [...this.links.values()]) link.close();
      this.links.clear();
    });

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
      friends: this.book.size,
      online: this.links.size,
    };
  }

  // --- friends ------------------------------------------------------------

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

    const { friend, isNew } = this.book.upsert(peer);
    this.log(`${isNew ? 'added' : 'updated'} ${friend.name} ${friend.id}`);
    this._connect(friend).catch(() => {});
    return friend;
  }

  removeFriend(id) {
    this.links.get(id)?.close();
    return this.book.delete(id);
  }

  resolve(query) {
    return this.book.resolve(query);
  }

  list() {
    return this.book.list((id) => this.links.has(id));
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

    // A link can die between 'ready' and here — the outbound path adopts a
    // microtask after the handshake resolves. Storing a dead one was permanent:
    // Link.close() has already emitted 'close' and dropped its listeners, so the
    // handler registered below would never fire, the friend stayed in this.links
    // forever, _redialAll skipped them for having a "live" link, and only a
    // restart brought them back.
    if (link.closed) {
      this.retry.penalise(peer.id);
      return;
    }

    if (this.links.has(peer.id)) {
      // Both sides dialled at once; keep the connection we already trust.
      link.close();
      return;
    }

    const { friend, isNew } = this.book.upsert(peer);
    this.links.set(peer.id, link);
    this.retry.reset(peer.id);

    if (isNew) this.log(`new peer accepted: ${friend.name} ${friend.id}`);
    this.log(`connected to ${friend.name}`);
    this.emit('status', { id: peer.id, name: friend.name, online: true });

    link.on('message', (frame) => this._onFrame(peer.id, frame));
    link.on('close', () => this._onLinkClosed(peer.id, friend, link));

    link.send({ t: 'endpoint', endpoints: this._localEndpoints() });
    this.messenger.flushOutbox(peer.id);
  }

  _onLinkClosed(peerId, friend, link) {
    if (this.links.get(peerId) !== link) return;
    this.links.delete(peerId);
    this.log(`lost ${friend.name}`);
    this.emit('status', { id: peerId, name: friend.name, online: false });
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

  _orderEndpoints(endpoints = []) {
    return orderEndpoints(endpoints, this.onion);
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
      const link = await raceEndpoints(
        endpoints,
        (endpoint) => this._dialEndpoint(endpoint, friend.id),
        (endpoint, error) => failures.push(explainDialFailure(endpoint, error))
      );

      if (link) {
        this._adopt(link);
        return { ok: true, reasons: [] };
      }
    } finally {
      this.dialing.delete(friend.id);
    }

    this.retry.penalise(friend.id);
    this._reportFailure(friend, failures, verbose);
    return { ok: false, reasons: failures };
  }

  /**
   * Say why a friend is unreachable. Repeats are suppressed unless the caller
   * asked for everything — /try always answers, a background redial does not
   * repeat itself forever.
   */
  _reportFailure(friend, failures, verbose) {
    const changed = this.retry.shouldReport(friend.id, failures.join('|'));
    if (!changed && !verbose) return;

    this.log(`could not reach ${friend.name}:`);
    for (const reason of failures) this.log(`  ${reason}`);
  }

  /**
   * Force an immediate attempt and report everything, for /try.
   *
   * Takes the same free text /chat and /forget take — a name, an ID or a
   * fragment of one — rather than an exact ID, because that is what a person
   * types and there is nowhere else in the UI they would get an exact ID from.
   */
  async probe(query) {
    const friend = this.book.resolve(query) || this.book.get(String(query || '').toUpperCase());
    if (!friend) throw new Error(`no single match for "${query}" — try /friends`);

    const describe = (extra) => ({
      name: friend.name,
      id: friend.id,
      endpoints: this._orderEndpoints(friend.endpoints),
      ...extra,
    });

    if (this.links.has(friend.id)) {
      return describe({ ok: true, alreadyOnline: true, reasons: [] });
    }

    this.retry.reset(friend.id);

    const result = (await this._connect(friend, { verbose: true })) || {
      ok: false,
      reasons: ['a connection attempt is already in progress'],
    };

    return describe({ ...result, alreadyOnline: false });
  }

  _redialAll() {
    const now = Date.now();
    for (const friend of this.book.values()) {
      if (this.links.has(friend.id) || this.dialing.has(friend.id)) continue;
      if (!this.retry.due(friend.id, now)) continue;
      if (!friend.endpoints?.length) continue;
      this._connect(friend).catch(() => {});
    }
  }

  // --- messages -----------------------------------------------------------

  _onFrame(peerId, frame) {
    const friend = this.book.get(peerId);
    if (!friend) return;

    switch (frame.t) {
      case 'msg':
        return this.messenger.receive(peerId, friend, frame);

      case 'ack':
        return this.messenger.acknowledge(peerId, frame);

      case 'profile':
        return this.book.rename(friend, frame);

      case 'endpoint':
        // Only onion addresses survive the merge, so a peer that sent an IP —
        // whether an old build or a hostile one — cannot get us to dial it.
        this.book.mergeEndpoints(friend, Array.isArray(frame.endpoints) ? frame.endpoints : []);
        return this.book.save();

      default:
        return undefined;
    }
  }

  sendText(peerId, body) {
    if (!this.book.has(peerId)) throw new Error('not a friend');
    return this.messenger.compose(peerId, body);
  }

  history(peerId, limit = 60) {
    return this.messenger.history(peerId, limit);
  }

  // --- kept for tests and callers that reach in ---------------------------

  _mergeEndpoints(friend, endpoints) {
    return this.book.mergeEndpoints(friend, endpoints);
  }

  get nextTry() {
    return this.retry.nextTry;
  }
}

module.exports = { TorChat, ONION_PORT };
