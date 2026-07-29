'use strict';

/**
 * The onion port belongs to the Endpoint model — it is a fact about addresses,
 * not about the engine's timing. Re-exported here so callers have one place to
 * look for everything the roster is configured by.
 */
const { ONION_PORT, MAX_ENDPOINTS } = require('../../models/endpoint');

const REDIAL_INTERVAL_MS = 30000;
const MAX_BACKOFF_MS = 300000;
const FIRST_BACKOFF_MS = 15000;
const DIAL_STAGGER_MS = 2000;

/**
 * Circuits are slow to build and slower to fail. A timeout tight enough for TCP
 * would abandon connections that were about to succeed.
 */
const DIAL_TIMEOUT_MS = 90000;

module.exports = {
  ONION_PORT,
  REDIAL_INTERVAL_MS,
  MAX_BACKOFF_MS,
  FIRST_BACKOFF_MS,
  DIAL_STAGGER_MS,
  DIAL_TIMEOUT_MS,
  MAX_ENDPOINTS,
};
