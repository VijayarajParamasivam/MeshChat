'use strict';

/**
 * Everything TorChat knows lives on this disk and nowhere else: your keys,
 * your friend list, and every conversation. There is no remote copy, which is
 * the point, so treat the identity file the way you'd treat a password.
 *
 * Conversations are held in memory while the app runs and written back on a
 * short debounce, because delivery receipts mutate messages that were already
 * saved and an append-only log would make that awkward.
 */

const fs = require('fs');
const path = require('path');

const HISTORY_CAP = 2000;
const SAVE_DEBOUNCE_MS = 300;

let root = null;
const conversations = new Map();
const pendingSaves = new Map();

function init(dir) {
  root = dir;
  fs.mkdirSync(path.join(root, 'messages'), { recursive: true });
}

/**
 * Drop everything held in memory.
 *
 * Conversations are cached in a module-level map, which is fine while one
 * identity owns the process — and wrong the moment a backup is restored over
 * it. Without this, the previous identity's history stayed in memory and was
 * written back to disk under the new one.
 */
function resetCache() {
  for (const timer of pendingSaves.values()) clearTimeout(timer);
  pendingSaves.clear();
  conversations.clear();
}

function filePath(...parts) {
  if (!root) throw new Error('store.init() must be called before use');
  return path.join(root, ...parts);
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

/** Write via a temp file and rename so a crash mid-write can't corrupt data. */
function writeJson(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

// --- identity -------------------------------------------------------------

function readIdentity() {
  return readJson(filePath('identity.json'), null);
}

function writeIdentity(identity) {
  writeJson(filePath('identity.json'), identity);
}

// --- friends --------------------------------------------------------------

function readFriends() {
  const list = readJson(filePath('friends.json'), []);
  return Array.isArray(list) ? list : [];
}

function writeFriends(friends) {
  writeJson(filePath('friends.json'), friends);
}

// --- conversations --------------------------------------------------------

function conversationFile(peerId) {
  return filePath('messages', `${peerId}.json`);
}

function loadConversation(peerId) {
  if (!conversations.has(peerId)) {
    const stored = readJson(conversationFile(peerId), []);
    conversations.set(peerId, Array.isArray(stored) ? stored : []);
  }
  return conversations.get(peerId);
}

function scheduleSave(peerId) {
  if (pendingSaves.has(peerId)) return;
  pendingSaves.set(
    peerId,
    setTimeout(() => {
      pendingSaves.delete(peerId);
      saveConversation(peerId);
    }, SAVE_DEBOUNCE_MS)
  );
}

function saveConversation(peerId) {
  const log = conversations.get(peerId);
  if (log) writeJson(conversationFile(peerId), log);
}

function appendMessage(peerId, message) {
  const log = loadConversation(peerId);
  log.push(message);
  if (log.length > HISTORY_CAP) log.splice(0, log.length - HISTORY_CAP);
  scheduleSave(peerId);
  return message;
}

/**
 * Patch a stored message in place, e.g. marking it delivered when an ack lands.
 *
 * `mine` scopes the search to one direction. Message IDs are chosen by whoever
 * composed the message, so the two directions share an ID space that neither
 * side controls both halves of. A peer picking an ID that collides with one of
 * ours could otherwise mark our message delivered by sending a message, or have
 * their message mistaken for a duplicate of ours. Nothing may match across the
 * boundary.
 */
function updateMessage(peerId, messageId, patch, mine = true) {
  const log = loadConversation(peerId);
  const found = log.find((m) => m.id === messageId && Boolean(m.mine) === mine);
  if (!found) return null;
  Object.assign(found, patch);
  scheduleSave(peerId);
  return found;
}

function recentMessages(peerId, limit = 60) {
  const log = loadConversation(peerId);
  return limit ? log.slice(-limit) : log.slice();
}

/** Have we already filed this message *from* the peer? Guards against a resend. */
function hasMessage(peerId, messageId) {
  return loadConversation(peerId).some((m) => m.id === messageId && !m.mine);
}

/**
 * Everything we composed that the peer has not acknowledged.
 *
 * Deliberately includes `sent`, not just `queued`. "Sent" only ever meant that
 * socket.write() accepted the bytes, which says nothing about whether they
 * survived the circuit — so a message written into a link that died a moment
 * later was never retried and never reported, it simply vanished. Only an ack
 * proves delivery, so only `delivered` is excluded here.
 */
function undelivered(peerId) {
  return loadConversation(peerId).filter((m) => m.mine && m.state !== 'delivered');
}

/** Force every pending write to disk. Called on quit. */
function flush() {
  for (const timer of pendingSaves.values()) clearTimeout(timer);
  pendingSaves.clear();
  for (const peerId of conversations.keys()) saveConversation(peerId);
}

// --- settings -------------------------------------------------------------

/**
 * Currently just the onion service key.
 *
 * It lives here rather than with the identity because it is a different kind of
 * secret. Losing the identity key costs you your name; losing this one costs you
 * your address, and every friend's card goes stale pointing at a service that no
 * longer answers.
 */
function readSettings() {
  return readJson(filePath('settings.json'), {});
}

function writeSettings(patch) {
  const next = { ...readSettings(), ...patch };
  writeJson(filePath('settings.json'), next);
  return next;
}

module.exports = {
  init,
  resetCache,
  readSettings,
  writeSettings,
  readIdentity,
  writeIdentity,
  readFriends,
  writeFriends,
  loadConversation,
  appendMessage,
  updateMessage,
  hasMessage,
  recentMessages,
  undelivered,
  flush,
  get root() {
    return root;
  },
};
