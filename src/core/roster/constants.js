'use strict';

/**
 * The port friends dial on the onion. Virtual — it exists only inside Tor, so it
 * never has to be free on this machine and is the same for everybody.
 */
const ONION_PORT = 47777;

const REDIAL_INTERVAL_MS = 30000;
const MAX_BACKOFF_MS = 300000;
const FIRST_BACKOFF_MS = 15000;
const DIAL_STAGGER_MS = 2000;

/**
 * Circuits are slow to build and slower to fail. A timeout tight enough for TCP
 * would abandon connections that were about to succeed.
 */
const DIAL_TIMEOUT_MS = 90000;

/** How many addresses to remember per friend. They almost always have one. */
const MAX_ENDPOINTS = 4;

module.exports = {
  ONION_PORT,
  REDIAL_INTERVAL_MS,
  MAX_BACKOFF_MS,
  FIRST_BACKOFF_MS,
  DIAL_STAGGER_MS,
  DIAL_TIMEOUT_MS,
  MAX_ENDPOINTS,
};
