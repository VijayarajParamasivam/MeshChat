'use strict';

/**
 * The public face of an identity: an ID, a display name, and a one-character
 * sigil.
 *
 * Only the ID means anything. It is a hash of a signing key, so it cannot be
 * claimed by anyone without that key. The name and sigil are labels their owner
 * chooses and can change at will — they arrive over the wire from someone else's
 * machine, so they are clamped here rather than trusted.
 *
 * The clamping used to be written out by hand in four places (identity
 * creation, profile edits, card parsing, and a peer renaming itself mid-session)
 * with slightly different rules in each. One of them forgot to trim.
 */

const MAX_NAME = 24;
const MAX_SIGIL = 2;

const DEFAULT_NAME = 'anon';
const DEFAULT_SIGIL = '*';

/**
 * A display name that is safe to store and print.
 * @param {*} value     whatever was supplied or received
 * @param {string} fallback  used when the value is empty or becomes empty
 */
function name(value, fallback = DEFAULT_NAME) {
  const text = String(value || fallback).trim().slice(0, MAX_NAME);
  return text || fallback;
}

/** A sigil: one or two characters, never more. */
function sigil(value, fallback = DEFAULT_SIGIL) {
  return String(value || fallback).slice(0, MAX_SIGIL);
}

/** The shape handed to the UI and put inside a contact card. */
function create(id, rawName, rawSigil) {
  return { id, name: name(rawName), sigil: sigil(rawSigil) };
}

module.exports = { create, name, sigil, MAX_NAME, MAX_SIGIL, DEFAULT_NAME, DEFAULT_SIGIL };
