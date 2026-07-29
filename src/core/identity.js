'use strict';

/**
 * Your identity is a pair of keys generated on this machine, and that's all.
 * There is no signup, no account server, and nothing to look you up in —
 * your TorChat ID is a hash of your own public key, so holding the private key
 * is the only proof of ownership that exists or is needed.
 */

const c = require('./crypto');
const store = require('./store');

let current = null;
let keys = null;

function hydrate(record) {
  current = record;
  keys = {
    signPrivate: c.importPrivate(record.sign.private),
    signPublic: record.sign.public,
    boxPrivate: c.importPrivate(record.box.private),
    boxPublic: record.box.public,
  };
  return current;
}

/** Load the identity from disk, or return null if this is a first run. */
function load() {
  const record = store.readIdentity();
  return record ? hydrate(record) : null;
}

/** Generate a brand new identity and persist it. */
function create(name, sigil = '*') {
  const signing = c.generateSigningPair();
  const box = c.generateBoxPair();
  const signPublic = c.exportPublic(signing.publicKey);

  const record = {
    id: c.deriveId(signPublic),
    name: String(name || 'anon').trim().slice(0, 24) || 'anon',
    sigil: String(sigil || '*').slice(0, 2),
    sign: { public: signPublic, private: c.exportPrivate(signing.privateKey) },
    box: {
      public: c.exportPublic(box.publicKey),
      private: c.exportPrivate(box.privateKey),
    },
    createdAt: Date.now(),
  };

  store.writeIdentity(record);
  return hydrate(record);
}

function get() {
  return current;
}

function getKeys() {
  if (!keys) throw new Error('no identity loaded');
  return keys;
}

/** The public half of who you are — what gets shared and shown to peers. */
function profile() {
  if (!current) return null;
  return { id: current.id, name: current.name, sigil: current.sigil };
}

function setProfile({ name, sigil }) {
  if (!current) throw new Error('no identity loaded');
  if (name) current.name = String(name).trim().slice(0, 24) || current.name;
  if (sigil) current.sigil = String(sigil).slice(0, 2);
  store.writeIdentity(current);
  return profile();
}

/**
 * Back up everything that cannot be regenerated. Anyone holding this file can be
 * you, so it never leaves the machine unless the user moves it.
 *
 * The onion key belongs in here as much as the signing key does. It lives in
 * settings rather than in the identity record because it is a different kind of
 * secret, but a "backup" that restored your name and lost your address would be
 * the worse half: every friend's saved card points at the onion, and an onion is
 * derived from this key alone. Leaving it out meant a restored identity was
 * unreachable by everyone who already knew you.
 */
function exportBackup() {
  if (!current) throw new Error('no identity loaded');
  const { onionKey } = store.readSettings();
  return JSON.stringify({ torchat: 1, identity: current, onionKey: onionKey || null }, null, 2);
}

function importBackup(json) {
  const parsed = JSON.parse(json);
  const record = parsed.identity || parsed;

  if (!record.sign?.private || !record.box?.private) {
    throw new Error('not a TorChat identity backup');
  }
  if (!c.idMatchesKey(record.id, record.sign.public)) {
    throw new Error('backup is corrupt: ID does not match its key');
  }

  // Prove the private half actually goes with the public one before adopting
  // it, rather than discovering it at the first handshake.
  try {
    const probe = c.sign(c.importPrivate(record.sign.private), 'torchat-backup-check');
    if (!c.verify(record.sign.public, 'torchat-backup-check', probe)) throw new Error();
    c.importPrivate(record.box.private);
  } catch {
    throw new Error('backup is corrupt: the private key does not match its public half');
  }

  store.writeIdentity(record);

  // Older backups predate this and simply have no onion key; that restores the
  // old behaviour of a fresh address rather than failing the import.
  if (parsed.onionKey) store.writeSettings({ onionKey: parsed.onionKey });

  return hydrate(record);
}

module.exports = {
  load,
  create,
  get,
  getKeys,
  profile,
  setProfile,
  exportBackup,
  importBackup,
};
