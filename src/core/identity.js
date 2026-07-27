'use strict';

/**
 * Your identity is a pair of keys generated on this machine, and that's all.
 * There is no signup, no account server, and nothing to look you up in —
 * your Mesh ID is a hash of your own public key, so holding the private key
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
    id: c.deriveMeshId(signPublic),
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
 * Back up the whole identity, private keys included. Anyone holding this file
 * can be you, so it never leaves the machine unless the user moves it.
 */
function exportBackup() {
  if (!current) throw new Error('no identity loaded');
  return JSON.stringify({ meshchat: 1, identity: current }, null, 2);
}

function importBackup(json) {
  const parsed = JSON.parse(json);
  const record = parsed.identity || parsed;

  if (!record.sign?.private || !record.box?.private) {
    throw new Error('not a MeshChat identity backup');
  }
  if (!c.idMatchesKey(record.id, record.sign.public)) {
    throw new Error('backup is corrupt: ID does not match its key');
  }

  store.writeIdentity(record);
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
