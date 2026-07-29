'use strict';

/**
 * Who you know: the friend list, its addresses, and how it reaches disk.
 *
 * Nothing here dials, listens, or touches the network — it is the record of who
 * exists and where they said they were. That separation is deliberate: the rule
 * that only onion addresses are ever stored lives in one function here, so there
 * is exactly one place to check that no IP can enter the friend list.
 */

const tor = require('../tor');
const { ONION_PORT, MAX_ENDPOINTS } = require('./constants');

class FriendBook {
  /**
   * @param {object} store   the persistence layer
   * @param {Function} onChange  called whenever the list is written
   */
  constructor(store, onChange = () => {}) {
    this.store = store;
    this.onChange = onChange;
    this.byId = new Map();
  }

  load() {
    for (const friend of this.store.readFriends()) this.byId.set(friend.id, friend);
    return this;
  }

  /** The underlying map. Callers read it; only this class writes it. */
  get all() {
    return this.byId;
  }

  get size() {
    return this.byId.size;
  }

  get(id) {
    return this.byId.get(id);
  }

  has(id) {
    return this.byId.has(id);
  }

  values() {
    return this.byId.values();
  }

  delete(id) {
    const existed = this.byId.delete(id);
    if (existed) this.save();
    return existed;
  }

  save() {
    this.store.writeFriends([...this.byId.values()]);
    this.onChange();
  }

  /**
   * Keep only onion endpoints, newest first, and never more than a handful.
   *
   * An IP arriving here — from an old build, or a hostile peer hoping we will
   * dial it and reveal ourselves — is dropped rather than deprioritised. There
   * is no ordering in which it could be used.
   */
  mergeEndpoints(friend, endpoints) {
    const seen = new Set();
    const merged = [];

    for (const e of [...endpoints, ...(friend.endpoints || [])]) {
      if (!e || !e.host || !tor.isOnion(e.host)) continue;
      const key = `${e.host}:${e.port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push({ type: 'onion', host: e.host, port: Number(e.port) || ONION_PORT });
    }

    friend.endpoints = merged.slice(0, MAX_ENDPOINTS);
  }

  /**
   * Record what a card or a live peer told us about themselves.
   *
   * @returns {{friend: object, isNew: boolean}}
   */
  upsert(peer) {
    let friend = this.byId.get(peer.id);
    const isNew = !friend;

    if (isNew) {
      friend = { id: peer.id, addedAt: Date.now(), endpoints: [] };
      this.byId.set(peer.id, friend);
    }

    if (this._isStale(friend, peer, isNew)) {
      // Still worth keeping as a fallback address, just not as the first choice.
      this.mergeEndpoints(friend, [...(friend.endpoints || []), ...(peer.endpoints || [])]);
    } else {
      this._apply(friend, peer);
    }

    this.save();
    return { friend, isNew };
  }

  /**
   * Is this card older than one we already hold?
   *
   * A card carries a signed timestamp, and until recently nothing looked at it.
   * An old card pasted after a newer one would quietly reinstate a dead onion
   * ahead of the live one in the dial order. Identity is still trusted — it is
   * proven by the key — but what the card *claims about now* is not, if we
   * already have something more recent.
   */
  _isStale(friend, peer, isNew) {
    const ts = Number(peer.ts) || 0;
    return Boolean(!isNew && friend.cardTs && ts && ts < friend.cardTs);
  }

  _apply(friend, peer) {
    friend.name = peer.name;
    friend.sigil = peer.sigil;
    friend.sign = peer.sign;
    friend.box = peer.box;

    const ts = Number(peer.ts) || 0;
    if (ts) friend.cardTs = ts;

    this.mergeEndpoints(friend, peer.endpoints || []);
  }

  /** Update the mutable, self-reported parts of a profile. */
  rename(friend, { name, sigil }) {
    friend.name = String(name || friend.name).slice(0, 24);
    friend.sigil = String(sigil || friend.sigil).slice(0, 2);
    this.save();
  }

  /** Look someone up by TorChat ID, a unique ID fragment, or display name. */
  resolve(query) {
    const q = String(query || '').trim();
    if (!q) return null;

    const upper = q.toUpperCase();
    if (this.byId.has(upper)) return this.byId.get(upper);

    const matches = [...this.byId.values()].filter(
      (f) =>
        f.id.replace(/-/g, '').includes(upper.replace(/-/g, '')) ||
        f.name.toLowerCase() === q.toLowerCase()
    );

    return matches.length === 1 ? matches[0] : null;
  }

  /** @param {Function} isOnline  id => boolean */
  list(isOnline) {
    return [...this.byId.values()].map((f) => ({
      id: f.id,
      name: f.name,
      sigil: f.sigil,
      online: isOnline(f.id),
      endpoints: f.endpoints || [],
    }));
  }
}

module.exports = { FriendBook };
