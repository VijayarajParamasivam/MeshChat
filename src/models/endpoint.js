'use strict';

/**
 * Where a peer can be reached: `{ type, host, port }`.
 *
 * In this app there is exactly one kind, and that is the whole privacy design.
 * An onion address is a public key rather than a location, so publishing one
 * tells nobody where you are — whereas a single IP endpoint slipping into a card
 * or a friend record would undo everything.
 *
 * `mergeOnions` is the choke point. Every path that could introduce an address —
 * parsing a card, a live peer announcing itself, loading the friend file — goes
 * through it, and anything that is not an onion is dropped rather than
 * deprioritised. There is no ordering in which a rejected address gets used.
 */

const tor = require('../core/tor');

/**
 * The port friends dial on the onion. Virtual — it exists only inside Tor, so it
 * never has to be free on this machine and is the same for everybody.
 */
const ONION_PORT = 47777;

/** How many addresses to remember per friend. They almost always have one. */
const MAX_ENDPOINTS = 4;

/** Our own address, as it goes into a contact card. */
function onion(host, port = ONION_PORT) {
  return { type: 'onion', host, port: Number(port) || ONION_PORT };
}

/** Is this something we are willing to dial? */
function isDialable(endpoint, ownOnion = null) {
  return Boolean(endpoint) && tor.isOnion(endpoint.host) && endpoint.host !== ownOnion;
}

/**
 * Normalise for signing into a card.
 *
 * The declared type is preserved rather than forced, because the card payload is
 * signed and has to serialise identically on both sides. Filtering happens when
 * a card is *read*, not when it is written.
 */
function forCard(endpoint) {
  return { type: endpoint.type, host: endpoint.host, port: Number(endpoint.port) };
}

/**
 * Combine incoming addresses with ones already on file: onions only, newest
 * first, no duplicates, and never more than a handful.
 */
function mergeOnions(incoming = [], existing = [], limit = MAX_ENDPOINTS) {
  const seen = new Set();
  const merged = [];

  for (const e of [...incoming, ...existing]) {
    if (!e || !e.host || !tor.isOnion(e.host)) continue;
    const key = `${e.host}:${e.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(onion(e.host, e.port));
  }

  return merged.slice(0, limit);
}

module.exports = { onion, isDialable, forCard, mergeOnions, ONION_PORT, MAX_ENDPOINTS };
