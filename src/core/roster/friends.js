'use strict';

/**
 * Who you know: the friend list, its addresses, and how it reaches disk.
 *
 * Nothing here dials, listens, or touches the network — it is the record of who
 * exists and where they said they were. That separation is deliberate: the rule
 * that only onion addresses are ever stored lives in one function here, so there
 * is exactly one place to check that no IP can enter the friend list.
 */

const Friend = require('../../models/friend');
const Endpoint = require('../../models/endpoint');

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
   * Fold new addresses into a friend's record.
   *
   * The filtering rule itself lives in the Endpoint model, because every path
   * that could introduce an address has to obey the same one.
   */
  mergeEndpoints(friend, endpoints) {
    friend.endpoints = Endpoint.mergeOnions(endpoints, friend.endpoints || []);
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
      friend = Friend.create(peer.id);
      this.byId.set(peer.id, friend);
    }

    if (Friend.isStale(friend, peer, isNew)) Friend.keepAsFallback(friend, peer);
    else Friend.applyCard(friend, peer);

    this.save();
    return { friend, isNew };
  }

  /** Update the mutable, self-reported parts of a profile. */
  rename(friend, patch) {
    Friend.rename(friend, patch);
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
    return [...this.byId.values()].map((f) => Friend.summarise(f, isOnline(f.id)));
  }
}

module.exports = { FriendBook };
