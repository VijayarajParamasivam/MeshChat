'use strict';

/**
 * Someone you know: their identity, what they call themselves, and where to
 * reach them.
 *
 *   id         a hash of their signing key — the only field that is proof
 *   sign, box  their public keys, taken from a signed card
 *   name, sigil  labels they chose, clamped because they came from elsewhere
 *   endpoints  onion addresses only, newest first
 *   cardTs     when the card we believe was made
 *   addedAt    when we first met them
 *
 * `cardTs` exists to settle a conflict. Cards are signed but not sequenced, so
 * pasting an old one after a newer one would otherwise reinstate a dead onion
 * ahead of the live one. Identity stays trusted — it is proven by the key — but
 * what a card *claims about now* is not, if we already hold something more
 * recent.
 */

const endpoint = require('./endpoint');
const profile = require('./profile');

/** A brand new record for someone we have just met. */
function create(id) {
  return { id, addedAt: Date.now(), endpoints: [] };
}

/** When was the card this record is based on made? 0 if we were never told. */
function cardTime(peer) {
  return Number(peer.ts) || 0;
}

/**
 * Is this card older than the one we already believe?
 *
 * Never true for someone new — there is nothing to be older than.
 */
function isStale(friend, peer, isNew) {
  const ts = cardTime(peer);
  return Boolean(!isNew && friend.cardTs && ts && ts < friend.cardTs);
}

/** Take everything a fresh card says about them. */
function applyCard(friend, peer) {
  friend.name = profile.name(peer.name);
  friend.sigil = profile.sigil(peer.sigil);
  friend.sign = peer.sign;
  friend.box = peer.box;

  const ts = cardTime(peer);
  if (ts) friend.cardTs = ts;

  friend.endpoints = endpoint.mergeOnions(peer.endpoints || [], friend.endpoints || []);
  return friend;
}

/**
 * Keep an older card's addresses as fallbacks without letting it overwrite the
 * profile or reorder the live address ahead of itself.
 */
function keepAsFallback(friend, peer) {
  friend.endpoints = endpoint.mergeOnions(friend.endpoints || [], peer.endpoints || []);
  return friend;
}

/** A peer renaming itself mid-session. Labels only — never keys or addresses. */
function rename(friend, { name, sigil }) {
  friend.name = profile.name(name, friend.name);
  friend.sigil = profile.sigil(sigil, friend.sigil);
  return friend;
}

/** What the UI is shown. Private-ish bookkeeping stays here. */
function summarise(friend, online) {
  return {
    id: friend.id,
    name: friend.name,
    sigil: friend.sigil,
    online,
    endpoints: friend.endpoints || [],
  };
}

module.exports = { create, applyCard, keepAsFallback, rename, summarise, isStale, cardTime };
