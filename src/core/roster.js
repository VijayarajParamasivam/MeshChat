'use strict';

/**
 * The engine. Owns the friend list, keeps links to everyone alive, and moves
 * messages between the UI and the wire.
 *
 * Connections are symmetric: either side may dial the other, and whoever gets
 * there first wins. A peer that dials in and proves its identity is accepted
 * automatically, because the only way it could know your address is that you
 * handed it your contact card in the first place. That means just one person
 * has to paste a code for a friendship to form.
 */

const { EventEmitter } = require('events');

const c = require('./crypto');
const card = require('./card');
const identity = require('./identity');
const lan = require('./lan');
const portal = require('./portal');
const punch = require('./punch');
const store = require('./store');
const tor = require('./tor');
const transport = require('./transport');

const BASE_PORT = 47777;
const PORT_ATTEMPTS = 10;
const REDIAL_INTERVAL_MS = 15000;
const MAX_BACKOFF_MS = 120000;
const NEARBY_TTL_MS = 30000;
const DIAL_TIMEOUT_MS = 6000;
const DIAL_STAGGER_MS = 400;
const CARD_REFRESH_MS = 60000;
const MAX_WARM_PEERS = 16;

/**
 * Offset for the listener-free port TCP simultaneous open uses. Chosen to clear
 * both the multi-instance range (BASE_PORT..+9) and the discovery port, so it is
 * derivable from the app port without anything extra in the contact card.
 */
const TCP_PUNCH_OFFSET = 100;

/**
 * Which protocol a socket ended up using. A dual-stack listener reports IPv4
 * peers as v4-mapped addresses like `::ffff:10.0.0.5`, which look like IPv6 if
 * you only check for a colon.
 */
function describeFamily(address) {
  if (!address) return 'unknown';
  if (address.startsWith('::ffff:')) return 'ipv4';
  return address.includes(':') ? 'ipv6' : 'ipv4';
}

function formatEndpoint(endpoint) {
  const host = String(endpoint.host);
  return host.includes(':')
    ? `[${host}]:${endpoint.port}`
    : `${host}:${endpoint.port}`;
}

/**
 * Turn a failed dial into something a human can act on. The distinction that
 * matters most: a refusal proves the packets got there, while a timeout means
 * they were silently dropped — which points at a firewall rather than a wrong
 * address.
 */
function explainDialFailure(endpoint, error) {
  const where = `${endpoint.type} ${formatEndpoint(endpoint)}`;

  switch (error.code) {
    case 'ETIMEDOUT':
      return `${where} — no reply. packets are being dropped: their firewall, router or ISP.`;
    case 'ECONNREFUSED':
      return `${where} — reachable, but nothing is listening. is meshchat running there?`;
    case 'ENETUNREACH':
      return `${where} — no route from here. this machine has no path to that address.`;
    case 'EHOSTUNREACH':
      return `${where} — host unreachable.`;
    case 'EHANDSHAKE':
      return `${where} — connected, but the handshake failed: ${error.message}`;
    default:
      return `${where} — ${error.message}`;
  }
}

/**
 * A failed punch says something a failed dial cannot. Dialling proves only that
 * *their* firewall dropped us; punching had both ends sending at once, so if
 * nothing crossed then at least one of the two networks refuses the technique
 * outright — which is the point at which no client-side change can help.
 */
function explainPunchFailure(endpoint, error) {
  const tcp = endpoint.type === 'tcp';
  const where = `punch ${tcp ? 'tcp ' : ''}${formatEndpoint(endpoint)}`;
  const protocol = tcp ? 'tcp' : 'udp';

  switch (error.code) {
    case 'EPUNCHFAIL':
      return `${where} — nothing crossed. either they were not running at the same time, or one of the two networks drops reciprocal ${protocol}.`;
    case 'EPUNCHLOST':
      return `${where} — the path opened then died: ${error.message}`;
    case 'ETIMEDOUT':
      return `${where} — packets crossed but the handshake stalled.`;
    case 'EHANDSHAKE':
      return `${where} — reached them, but the handshake failed: ${error.message}`;
    default:
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
    this.nearby = new Map();
    this.lastFailure = new Map();

    this.server = null;
    this.beacon = null;
    this.tor = null;
    this.onion = null;
    this.hub = null;
    this.punching = new Set();
    this.port = null;
    this.cardCode = null;
    this.redialTimer = null;
    this.cardTimer = null;
    this.lastEndpointSignature = null;
  }

  log(text) {
    this.emit('log', text);
  }

  // --- lifecycle ----------------------------------------------------------

  /**
   * Private mode: your address must not be learnable by anybody, including the
   * friend you are talking to.
   *
   * That is a stronger claim than "we use Tor", and it takes more than adding an
   * onion address. Every other way this app reveals where it is has to be shut
   * off too — the card must carry no IP, the endpoint announcements that keep
   * rotating addresses fresh must stop, the router must not be asked for a
   * pinhole, and the multicast beacon must stop naming us on the local network.
   * One of those left running would quietly undo the rest.
   */
  get private() {
    return Boolean(store.readSettings().private);
  }

  get torEnabled() {
    const settings = store.readSettings();
    return Boolean(settings.tor || settings.private);
  }

  async start() {
    for (const friend of store.readFriends()) this.friends.set(friend.id, friend);

    this.port = await this._bindPort();
    // Build a LAN-only card straight away so connections arriving during the
    // (slow) router negotiation still have something valid to greet them with.
    this._rebuildCard();
    this.log(`listening on tcp ${this.port}`);

    if (this.torEnabled) await this._startTor();

    // Everything below reaches out to the network or announces us on it, and in
    // private mode all of it is a leak rather than a feature. Tor already made
    // us reachable without any of it.
    if (this.private) {
      this._rebuildCard();
      this.log('private mode: no ip is published, announced or asked for');
      this.redialTimer = setInterval(() => this._redialAll(), REDIAL_INTERVAL_MS);
      this._redialAll();
      return;
    }

    const status = await portal.open(this.port, { onLog: (m) => this.log(m) });
    this._rebuildCard();
    this.emit('portal', status);

    if (status.ip6Reachable) {
      this.log(`portal: reachable over IPv6 at [${status.ip6[0]}]:${this.port}`);
    } else if (status.ipv4Reachable) {
      this.log(
        `portal: reachable over IPv4 at ${status.externalIp}:${status.externalPort} (${status.method})`
      );
    } else {
      this.log('portal: no public address — same-network chat only');
      this.log(status.ipv4Note);
    }

    await this._startHub();

    this.beacon = new lan.LanBeacon();
    this.beacon.on('log', (m) => this.log(m));
    this.beacon.on('peer', (peer) => this._onLanPeer(peer));
    this.beacon.start({ id: identity.get().id, port: this.port });

    // Record the current address set as the baseline, then watch for it moving.
    this._refreshEndpoints();
    this.cardTimer = setInterval(() => this._refreshEndpoints(), CARD_REFRESH_MS);

    this.redialTimer = setInterval(() => this._redialAll(), REDIAL_INTERVAL_MS);
    this._redialAll();
  }

  async _bindPort() {
    for (let i = 0; i < PORT_ATTEMPTS; i++) {
      const port = BASE_PORT + i;
      try {
        this.server = await transport.listen(port, () => this._context(), (link) =>
          this._onInbound(link)
        );
        return port;
      } catch (err) {
        if (err.code !== 'EADDRINUSE') throw err;
      }
    }
    throw new Error('no free port in range');
  }

  /**
   * Bring up Tor and publish an onion service pointing at our listener.
   *
   * The onion needs no firewall traversal of any kind: Tor only ever makes
   * outbound connections, and outbound is the one thing every carrier permits.
   * The service simply forwards to the TCP listener already running, so nothing
   * above this line — handshake, framing, encryption — knows the difference.
   *
   * Failure is not fatal unless private mode is on, where falling back to
   * direct connections would publish the address the user asked to hide.
   */
  async _startTor() {
    try {
      this.tor = new tor.Tor({
        dataDir: require('path').join(store.root, 'tor'),
        onionKey: store.readSettings().onionKey || null,
      });
      this.tor.on('log', (m) => this.log(m));

      await this.tor.start();
      const { address, key } = await this.tor.publish(this.port, this.port);

      this.onion = address;
      // Saved so the address survives a restart — it is derived from this key,
      // and losing it makes every friend's card point at nothing.
      if (key) store.writeSettings({ onionKey: key });

      this._rebuildCard();
      return true;
    } catch (err) {
      this.tor = null;
      this.onion = null;

      if (err.code === 'ENOTOR') {
        for (const row of err.hint || [err.message]) this.log(row);
      } else {
        this.log(`tor: ${err.message}`);
      }

      if (this.private) {
        // Refusing to start is the safe failure. Quietly carrying on over plain
        // IP would hand out the address the user turned this on to conceal.
        throw new Error(
          'private mode needs Tor, and Tor did not start. Nothing was published.'
        );
      }
      return false;
    }
  }

  /**
   * Bring up the hole-punching socket. UDP and TCP port numbers live in separate
   * spaces, so this shares the number the TCP listener already took — which is
   * what we want, since the peer only ever learns one port from our card.
   *
   * Failure here is not fatal. Punching is the path of last resort; if the
   * socket will not bind, every ordinary route still works.
   */
  async _startHub() {
    // A second instance on this machine takes the next TCP port up, which lands
    // exactly on the multicast beacon's UDP port. Both would bind it with
    // reuseAddr and then quietly steal each other's datagrams. Punching is for
    // peers on different networks, so the second instance simply goes without.
    if (this.port === lan.PORT) {
      this.log('hole punching off: this port collides with lan discovery');
      return;
    }

    try {
      this.hub = new punch.Hub(this.port);
      this.hub.on('log', (m) => this.log(m));
      this.hub.on('session', (stream) => this._onPunchedIn(stream));
      await this.hub.start();
      this.log(`hole punching ready on udp ${this.port}`);
    } catch (err) {
      this.hub = null;
      this.log(`hole punching unavailable: ${err.message}`);
    }
  }

  /**
   * Decide whose pinholes to hold open.
   *
   * Only friends with an IPv6 address, since that is the only kind punching can
   * work for, and only those we aren't already connected to. Capped so a large
   * friend list can't turn into a steady stream of background traffic on a
   * metered mobile connection.
   */
  _updateWarmSet() {
    if (!this.hub) return;

    this.hub.coolAll();

    let warmed = 0;
    for (const friend of this.friends.values()) {
      if (warmed >= MAX_WARM_PEERS) break;
      if (this.links.has(friend.id)) continue;

      for (const endpoint of friend.endpoints || []) {
        if (endpoint.type !== 'ip6' || this._isSelf(endpoint)) continue;
        // Warm every port we can punch from — there is no way to know in advance
        // which one their carrier will let through.
        for (const fromPort of this.hub.ports()) {
          this.hub.keepWarm(
            endpoint.host,
            fromPort === this.port ? endpoint.port : fromPort,
            fromPort
          );
        }
        warmed += 1;
        break; // one address per friend is enough to keep a path open
      }
    }
  }

  /** A peer punched through to us before we managed to reach them. */
  async _onPunchedIn(stream) {
    try {
      const link = await transport.overStream(stream, this._context());
      this._adopt(link);
    } catch (err) {
      this.log(`punched-in peer failed the handshake: ${err.message}`);
    }
  }

  /**
   * Last resort: punch a hole to a friend neither of us can dial.
   *
   * Only IPv6 endpoints are worth trying. Behind IPv4 NAT the port we send from
   * is rewritten to something neither side can predict, so the two flows never
   * line up — that is the problem STUN exists to solve, and solving it means
   * involving a third party we have deliberately ruled out. With IPv6 the
   * addresses and ports are ours, unchanged end to end, so the flows match by
   * construction.
   */
  async _punchTo(friend, { aligned = true, verbose = false } = {}) {
    if (!this.hub) return null;
    if (this.links.has(friend.id) || this.punching.has(friend.id)) return null;

    const targets = (friend.endpoints || []).filter(
      (e) => e.type === 'ip6' && !this._isSelf(e)
    );
    if (!targets.length) return null;

    const reasons = [];
    this.punching.add(friend.id);
    try {
      for (const endpoint of targets) {
        if (verbose) {
          const wait = aligned ? punch.msUntilWindow() : 0;
          this.log(
            `punching ${formatEndpoint(endpoint)} — firing in ${(wait / 1000).toFixed(1)}s, ` +
              'their machine must be running too'
          );
        }

        // Every port at once, not one after another. Each waits for the same
        // shared window, so running them in sequence would spend a fresh window
        // on each and stretch one attempt into minutes. They use separate
        // sockets and cannot interfere.
        const attempts = this.hub.ports().map(async (fromPort) => {
          const toPort = fromPort === this.port ? endpoint.port : fromPort;
          const via = fromPort === this.port ? endpoint : { ...endpoint, port: toPort };

          try {
            const stream = await this.hub.punch(endpoint.host, toPort, { aligned, fromPort });
            return await transport.overStream(stream, this._context(), friend.id);
          } catch (err) {
            throw Object.assign(err, { via });
          }
        });

        const settled = await Promise.allSettled(attempts);
        const won = settled.find((r) => r.status === 'fulfilled');

        if (won) {
          // Any slower port that also got through is redundant once one link is
          // adopted; drop the extras rather than leaving them running.
          for (const other of settled) {
            if (other.status === 'fulfilled' && other.value !== won.value) other.value.close();
          }
          this._adopt(won.value);
          return { ok: true, reasons: [] };
        }

        for (const failed of settled) {
          reasons.push(explainPunchFailure(failed.reason.via || endpoint, failed.reason));
        }

        // UDP got nowhere. Some carriers filter it while passing TCP, so the
        // same trick is worth one attempt over the other protocol before
        // concluding the network refuses the technique altogether.
        try {
          if (verbose) this.log(`  udp failed — retrying over tcp ${endpoint.port + TCP_PUNCH_OFFSET}`);
          const link = await transport.simultaneousOpen(
            endpoint.host,
            endpoint.port + TCP_PUNCH_OFFSET,
            this.port + TCP_PUNCH_OFFSET,
            this._context(),
            friend.id
          );
          this._adopt(link);
          return { ok: true, reasons: [] };
        } catch (err) {
          reasons.push(
            explainPunchFailure(
              { ...endpoint, type: 'tcp', port: endpoint.port + TCP_PUNCH_OFFSET },
              err
            )
          );
        }
      }
      return { ok: false, reasons };
    } finally {
      this.punching.delete(friend.id);
    }
  }

  async stop() {
    clearInterval(this.redialTimer);
    clearInterval(this.cardTimer);
    if (this.beacon) this.beacon.stop();
    if (this.hub) this.hub.stop();
    // Killing tor takes the onion service down with it, so we stop being
    // advertised rather than staying published and unanswered.
    if (this.tor) this.tor.stop();
    for (const link of this.links.values()) link.close();
    this.links.clear();
    if (this.server) this.server.close();
    await portal.close();
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

  /** Every address a friend could currently reach us on, best first. */
  _localEndpoints() {
    // In private mode the onion is the whole list. Not "first" — the only one.
    // An IP alongside it would be handed to the peer in the card and in every
    // endpoint announcement, which is exactly what was meant to be hidden.
    if (this.private) {
      return this.onion ? [{ type: 'onion', host: this.onion, port: this.port }] : [];
    }

    const status = portal.status() || {};
    const lanIp = status.lanIp || portal.lanAddress();
    const ip6 = status.ip6 || portal.globalIPv6Addresses();
    const endpoints = [];

    // IPv6 leads. These addresses are globally routable with no NAT in the way,
    // so they're the ones most likely to connect on the first try.
    for (const host of ip6) {
      endpoints.push({ type: 'ip6', host, port: this.port });
    }

    if (status.externalIp && status.externalPort && !portal.isPrivate(status.externalIp)) {
      endpoints.push({ type: 'wan', host: status.externalIp, port: status.externalPort });
    }
    if (lanIp) {
      endpoints.push({ type: 'lan', host: lanIp, port: this.port });
    }

    return endpoints;
  }

  _rebuildCard() {
    this.cardCode = card.create(
      identity.profile(),
      identity.getKeys(),
      this._localEndpoints()
    );
    return this.cardCode;
  }

  /**
   * IPv6 privacy addresses rotate every couple of hours, and IPv4 leases change
   * too. Re-check ours periodically; if they moved, tell everyone we're talking
   * to so their stored copy stays dialable rather than going stale.
   */
  _refreshEndpoints() {
    const endpoints = this._localEndpoints();
    const signature = JSON.stringify(endpoints);
    if (signature === this.lastEndpointSignature) return;

    const isFirstCheck = this.lastEndpointSignature === null;
    this.lastEndpointSignature = signature;
    this._rebuildCard();
    if (isFirstCheck) return;

    this.log('our address changed — telling connected friends');
    for (const link of this.links.values()) {
      link.send({ t: 'endpoint', endpoints });
    }
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

  // --- friends ------------------------------------------------------------

  _saveFriends() {
    store.writeFriends([...this.friends.values()]);
    this.emit('friends-changed');
  }

  /** Merge endpoints, newest first, without letting the list grow unbounded. */
  _mergeEndpoints(friend, endpoints) {
    const seen = new Set();
    const merged = [];
    for (const e of [...endpoints, ...(friend.endpoints || [])]) {
      if (!e || !e.host || !e.port) continue;
      const key = `${e.host}:${e.port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push({ type: e.type || 'wan', host: e.host, port: Number(e.port) });
    }
    friend.endpoints = merged.slice(0, 6);
  }

  _upsertFriend(peer, extraEndpoints = []) {
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
    this._mergeEndpoints(friend, [...extraEndpoints, ...(peer.endpoints || [])]);

    this._saveFriends();
    return { friend, isNew };
  }

  /**
   * Add someone from a pasted contact code, or by Mesh ID if they're currently
   * visible on the local network.
   */
  async addFriend(input) {
    const text = String(input || '').trim();

    if (text.startsWith(card.PREFIX)) {
      const peer = card.parse(text);
      if (peer.id === identity.get().id) throw new Error('that is your own code');

      const { friend, isNew } = this._upsertFriend(peer);
      this.log(`${isNew ? 'added' : 'updated'} ${friend.name} ${friend.id}`);
      this._connect(friend).catch(() => {});
      return friend;
    }

    const meshId = text.toUpperCase();
    const seen = this.nearby.get(meshId);
    if (!seen) {
      throw new Error(
        'paste a MESH1 code, or a Mesh ID of someone shown by /nearby'
      );
    }

    const link = await transport.dial(seen.host, seen.port, this._context(), meshId);
    this._adopt(link, [{ type: 'lan', host: seen.host, port: seen.port }]);
    return this.friends.get(meshId);
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

  nearbyList() {
    const now = Date.now();
    return [...this.nearby.entries()]
      .filter(([, v]) => now - v.seen < NEARBY_TTL_MS)
      .map(([id, v]) => ({ id, host: v.host, port: v.port, known: this.friends.has(id) }));
  }

  // --- connections --------------------------------------------------------

  _onInbound(link) {
    link.once('ready', () => {
      // Remember the address they actually arrived from. When a friend's address
      // changes, this is usually how we learn the new one — effectively they act
      // as our address oracle, with no third party needed to report it.
      //
      // Not over Tor, though. A peer arriving through the onion service appears
      // to come from 127.0.0.1, which is neither true nor useful, and recording
      // it would put a bogus endpoint in their card. In private mode the whole
      // idea is unwanted anyway: we do not want to know where they are.
      const host = (link.remoteAddress || '').replace(/^::ffff:/, '');
      const viaTor = this.private || host === '127.0.0.1' || host === '::1';
      const listenPort = link.peer.endpoints?.[0]?.port;
      const type = describeFamily(link.remoteAddress) === 'ipv6' ? 'ip6' : 'wan';
      const observed =
        !viaTor && host && listenPort ? [{ type, host, port: listenPort }] : [];
      this._adopt(link, observed);
    });
    link.once('failed', (reason) => this.log(`rejected inbound link: ${reason}`));
  }

  _adopt(link, extraEndpoints = []) {
    const peer = link.peer;

    if (this.links.has(peer.id)) {
      // Both sides dialled at once; keep the connection we already trust.
      link.close();
      return;
    }

    const { friend, isNew } = this._upsertFriend(peer, extraEndpoints);
    this.links.set(peer.id, link);
    this.attempts.delete(peer.id);
    this.nextTry.delete(peer.id);

    if (isNew) this.log(`new peer accepted: ${friend.name} ${friend.id}`);
    this.log(`connected to ${friend.name} over ${describeFamily(link.remoteAddress)}`);
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

  async _connect(friend, { verbose = false } = {}) {
    if (this.links.has(friend.id) || this.dialing.has(friend.id)) return null;
    // A punch waits for the shared clock boundary and can outlast the redial
    // timer, so it needs its own guard or the next tick starts a second attempt
    // on top of the one still waiting.
    if (this.punching.has(friend.id)) return null;

    const endpoints = this._orderEndpoints(friend.endpoints);
    if (!endpoints.length) {
      if (verbose) this.log(`${friend.name} has no address we can dial`);
      return { ok: false, reasons: ['their card contains no reachable address'] };
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

    // Every ordinary route was dropped. If they have an IPv6 address, both of us
    // sending at the same instant can still get through where either of us
    // sending alone cannot.
    const punched = await this._punchTo(friend, { verbose });
    if (punched?.ok) return { ok: true, reasons: [] };
    if (punched) failures.push(...punched.reasons);

    this._backOff(friend.id);
    this._reportFailure(friend, failures, verbose);
    return { ok: false, reasons: failures };
  }

  /**
   * Say why a friend is unreachable, but only when the reason changes —
   * otherwise a permanently offline friend would spam the log every 15 seconds.
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
   * Force a hole-punch attempt on its own, for /punch.
   *
   * Kept separate from `probe` because it demands something of the user that no
   * other command does: the friend has to be sitting in front of their machine
   * with MeshChat open at the same moment. Reporting how long until the shared
   * window opens is what makes that coordination possible.
   */
  async punchProbe(friendId) {
    const friend = this.friends.get(friendId);
    if (!friend) throw new Error('not a friend');
    if (!this.hub) {
      return { ok: false, reasons: ['hole punching is not running on this machine'] };
    }
    if (this.links.has(friendId)) {
      return { ok: true, alreadyOnline: true, reasons: [] };
    }

    const targets = (friend.endpoints || []).filter((e) => e.type === 'ip6');
    if (!targets.length) {
      return {
        ok: false,
        reasons: ['their card has no ipv6 address — punching cannot work over ipv4 nat'],
      };
    }

    this.attempts.delete(friendId);
    this.nextTry.delete(friendId);

    const result = await this._punchTo(friend, { verbose: true });
    return result || { ok: false, reasons: ['a punch is already in progress'] };
  }

  torStatus() {
    const settings = store.readSettings();
    return {
      binary: tor.find(),
      hint: tor.installHint(),
      running: Boolean(this.tor?.ready),
      onion: this.onion,
      port: this.port,
      enabled: Boolean(settings.tor),
      private: Boolean(settings.private),
    };
  }

  /**
   * Turn Tor or private mode on or off.
   *
   * Takes effect on restart rather than live. Publishing an onion, tearing down
   * the beacon and withdrawing a port mapping midway through a session leaves a
   * window where some of the old state is still advertised, and for a setting
   * whose whole purpose is "reveal nothing" a half-applied state is worse than
   * asking the user to restart.
   */
  setTor({ enabled, isPrivate }) {
    const patch = {};
    if (enabled !== undefined) patch.tor = Boolean(enabled);
    if (isPrivate !== undefined) {
      patch.private = Boolean(isPrivate);
      if (isPrivate) patch.tor = true; // private mode has no meaning without it
    }
    return store.writeSettings(patch);
  }

  /** Seconds until the next shared punch window, so both ends can line up. */
  nextPunchWindowMs() {
    return punch.msUntilWindow();
  }

  /**
   * Dial one endpoint by whichever route its type calls for.
   *
   * An onion address goes through Tor's SOCKS port and comes back as an ordinary
   * socket, so the handshake above it is identical either way — the same reason
   * the punched UDP session could be dropped in unchanged.
   */
  _dialEndpoint(endpoint, expectId) {
    if (endpoint.type === 'onion' || tor.isOnion(endpoint.host)) {
      if (!this.tor?.ready) {
        const error = new Error('tor is not running, so onion addresses cannot be dialled');
        error.code = 'ENOTOR';
        return Promise.reject(error);
      }
      return this.tor
        .dial(endpoint.host, endpoint.port)
        .then((socket) => transport.overStream(socket, this._context(), expectId, tor.DIAL_TIMEOUT_MS));
    }

    // Never let a plain IP be dialled while private mode is on: the connection
    // itself would reveal this machine's address to whatever is at the far end.
    if (this.private) {
      const error = new Error('private mode refuses to dial anything but an onion address');
      error.code = 'EPRIVATE';
      return Promise.reject(error);
    }

    return transport.dial(endpoint.host, endpoint.port, this._context(), expectId, DIAL_TIMEOUT_MS);
  }

  /**
   * Try every known address, best first, starting each a moment after the last.
   * Whichever completes its handshake first wins and the rest are dropped.
   *
   * Dialling one at a time meant a friend with two IPv6 addresses and two IPv4
   * ones could stack up four timeouts before failing. Staggering rather than
   * firing all at once means the preferred address usually wins outright, so we
   * rarely open a connection only to throw it away.
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

  /**
   * A friend's stored endpoints can go stale — most often after a restart when
   * ports get reassigned, leaving an address that now points back at us.
   */
  _isSelf(endpoint) {
    if (endpoint.port !== this.port) return false;
    const status = portal.status() || {};
    const mine = [
      status.lanIp,
      portal.lanAddress(),
      '127.0.0.1',
      '::1',
      'localhost',
      ...(status.ip6 || portal.globalIPv6Addresses()),
    ];
    return mine.includes(endpoint.host);
  }

  /**
   * Best address first. IPv6 wins outright — no NAT, no port mapping, nothing to
   * negotiate. After that, an IPv4 address on our own subnet, then the router's
   * public address. A LAN address on some *other* subnet is worthless, so it goes last.
   */
  _orderEndpoints(endpoints = []) {
    // Private mode has exactly one kind of address it is willing to use.
    if (this.private) {
      return endpoints.filter((e) => e.type === 'onion' || tor.isOnion(e.host));
    }

    const prefix = portal.lanAddress().split('.').slice(0, 3).join('.');
    const score = (e) => {
      if (e.type === 'onion' || tor.isOnion(e.host)) return 4;
      if (e.type === 'ip6') return 0;
      if (e.host.startsWith(`${prefix}.`)) return 1;
      if (e.type === 'lan') return 3;
      return 2;
    };
    // Onion sorts last, not because it is worst but because it is slowest: a
    // circuit costs seconds where a direct dial costs milliseconds. It is the
    // one that always works, so it is the one worth waiting for.
    return [...endpoints]
      .filter((e) => !this._isSelf(e))
      .filter((e) => e.type !== 'onion' || this.tor?.ready)
      .sort((a, b) => score(a) - score(b));
  }

  _backOff(id) {
    const attempts = (this.attempts.get(id) || 0) + 1;
    this.attempts.set(id, attempts);
    const delay = Math.min(MAX_BACKOFF_MS, 5000 * 2 ** (attempts - 1));
    this.nextTry.set(id, Date.now() + delay);
  }

  _redialAll() {
    // Recomputed on every sweep rather than tracked incrementally: the inputs
    // (friend list, live links, rotating addresses) all move on their own, and
    // rebuilding a set this small is cheaper than keeping it correct by hand.
    this._updateWarmSet();

    const now = Date.now();
    for (const friend of this.friends.values()) {
      if (this.links.has(friend.id) || this.dialing.has(friend.id)) continue;
      if (this.punching.has(friend.id)) continue;
      if ((this.nextTry.get(friend.id) || 0) > now) continue;
      if (!friend.endpoints?.length) continue;
      this._connect(friend).catch(() => {});
    }
  }

  _onLanPeer(peer) {
    this.nearby.set(peer.id, { host: peer.host, port: peer.port, seen: Date.now() });

    const friend = this.friends.get(peer.id);
    if (!friend) return;

    this._mergeEndpoints(friend, [{ type: 'lan', host: peer.host, port: peer.port }]);

    if (!this.links.has(peer.id) && !this.dialing.has(peer.id)) {
      this.nextTry.delete(peer.id);
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

  portalStatus() {
    return portal.status();
  }
}

module.exports = { Mesh };
