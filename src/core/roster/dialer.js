'use strict';

/**
 * Deciding what to dial, in what order, and how long to sulk after a failure.
 *
 * Everything here is either a pure function or a small bag of retry state, so
 * the policy can be reasoned about — and tested — without a circuit, a socket,
 * or a running Tor anywhere in sight. The actual dialling is injected.
 */

const Endpoint = require('../../models/endpoint');
const { DIAL_STAGGER_MS, FIRST_BACKOFF_MS, MAX_BACKOFF_MS } = require('./constants');

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
        return `${where} — their torchat is not running.`;
      }
      return `${where} — ${error.message}`;
  }
}

/**
 * Onion addresses only, and never our own.
 *
 * The filter is the same one that guards the friend list, applied again at the
 * moment of use. An address that somehow got stored can still never be dialled.
 */
function orderEndpoints(endpoints = [], ownOnion = null) {
  return (endpoints || []).filter((e) => Endpoint.isDialable(e, ownOnion));
}

/**
 * Try each known address, staggered, and resolve with the first link that comes
 * up. Friends almost always have exactly one address, so this matters only just
 * after somebody's has changed and both the old and new are on record.
 *
 * @param {Array}    endpoints
 * @param {Function} dial       endpoint => Promise<Link>
 * @param {Function} onFailure  (endpoint, error) => void
 * @returns {Promise<object|null>}
 */
function raceEndpoints(endpoints, dial, onFailure = () => {}) {
  return new Promise((resolve) => {
    let settled = false;
    let pending = endpoints.length;
    const timers = [];

    const finish = (link) => {
      if (settled) {
        // A straggler that won a race already decided. Nothing will adopt it.
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
          dial(endpoint)
            .then(finish)
            .catch((error) => onFailure(endpoint, error))
            .finally(oneDone);
        }, index * DIAL_STAGGER_MS)
      );
    });
  });
}

/**
 * How long to leave a friend alone after a failed attempt, and whether their
 * latest failure is worth mentioning again.
 */
class RetryPolicy {
  constructor() {
    this.attempts = new Map();
    this.nextTry = new Map();
    this.lastFailure = new Map();
  }

  /** Double the wait, up to the ceiling. */
  penalise(id) {
    const attempts = (this.attempts.get(id) || 0) + 1;
    this.attempts.set(id, attempts);
    const delay = Math.min(MAX_BACKOFF_MS, FIRST_BACKOFF_MS * 2 ** (attempts - 1));
    this.nextTry.set(id, Date.now() + delay);
  }

  due(id, now = Date.now()) {
    return (this.nextTry.get(id) || 0) <= now;
  }

  reset(id) {
    this.attempts.delete(id);
    this.nextTry.delete(id);
    this.lastFailure.delete(id);
  }

  /**
   * Say why a friend is unreachable, but only when the reason changes —
   * otherwise a permanently offline friend would spam the log forever.
   */
  shouldReport(id, signature) {
    if (this.lastFailure.get(id) === signature) return false;
    this.lastFailure.set(id, signature);
    return true;
  }
}

module.exports = { explainDialFailure, orderEndpoints, raceEndpoints, RetryPolicy };
