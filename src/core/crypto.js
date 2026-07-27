'use strict';

/**
 * All cryptography for MeshChat, built on Node's built-in crypto module.
 *
 * Two key types are used per identity:
 *   - Ed25519 for signing. This IS the identity: your Mesh ID is derived from
 *     the public half, so proving you hold the private half proves you are you.
 *   - X25519 for key agreement. Ed25519 keys cannot do ECDH, so a second pair
 *     is needed to derive the shared secret that encrypts the channel.
 */

const crypto = require('crypto');

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// --- encoding helpers -----------------------------------------------------

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

function unb64u(str) {
  return Buffer.from(str, 'base64url');
}

// --- key generation -------------------------------------------------------

function generateSigningPair() {
  return crypto.generateKeyPairSync('ed25519');
}

function generateBoxPair() {
  return crypto.generateKeyPairSync('x25519');
}

// --- key serialisation ----------------------------------------------------

function exportPublic(key) {
  return b64u(key.export({ type: 'spki', format: 'der' }));
}

function exportPrivate(key) {
  return b64u(key.export({ type: 'pkcs8', format: 'der' }));
}

function importPublic(encoded) {
  return crypto.createPublicKey({
    key: unb64u(encoded),
    format: 'der',
    type: 'spki',
  });
}

function importPrivate(encoded) {
  return crypto.createPrivateKey({
    key: unb64u(encoded),
    format: 'der',
    type: 'pkcs8',
  });
}

// --- signing --------------------------------------------------------------

/** Sign a buffer or string with an Ed25519 private key. */
function sign(privateKey, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  return b64u(crypto.sign(null, buf, privateKey));
}

/**
 * Verify a signature against an exported Ed25519 public key.
 * Returns false rather than throwing on malformed input, since this runs on
 * data that arrived over the wire from an untrusted peer.
 */
function verify(publicKeyEncoded, data, signature) {
  try {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    return crypto.verify(null, buf, importPublic(publicKeyEncoded), unb64u(signature));
  } catch {
    return false;
  }
}

// --- identity ------------------------------------------------------------

/**
 * Derive the human-facing Mesh ID from an exported Ed25519 public key.
 *
 * SHA-256 the key, render the first 60 bits in Crockford base32 (no I/L/O/U,
 * so it survives being read aloud or copied by hand), and group it for legibility:
 *   MESH-4K7P-9XQ2-M3TV
 *
 * Because the ID is a hash of the key, nobody can claim yours without your
 * private key. That property is what replaces a server-side account registry.
 */
function deriveMeshId(publicKeyEncoded) {
  const hash = crypto.createHash('sha256').update(unb64u(publicKeyEncoded)).digest();

  let bits = '';
  for (let i = 0; i < 8; i++) bits += hash[i].toString(2).padStart(8, '0');

  let out = '';
  for (let i = 0; i < 12; i++) {
    out += CROCKFORD[parseInt(bits.slice(i * 5, i * 5 + 5), 2)];
  }

  return `MESH-${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}`;
}

/** Check that a Mesh ID really is the hash of the key claiming it. */
function idMatchesKey(meshId, publicKeyEncoded) {
  try {
    return deriveMeshId(publicKeyEncoded) === meshId;
  } catch {
    return false;
  }
}

// --- encrypted channel ----------------------------------------------------

/**
 * Derive the symmetric channel key from our X25519 private key and the peer's
 * public one. Both sides compute the identical secret without it ever crossing
 * the wire. The HKDF salt is the two public keys sorted, so both ends agree on
 * it regardless of who dialled whom.
 */
function deriveChannelKey(myBoxPrivate, theirBoxPublicEncoded) {
  const shared = crypto.diffieHellman({
    privateKey: myBoxPrivate,
    publicKey: importPublic(theirBoxPublicEncoded),
  });

  const mine = exportPublic(crypto.createPublicKey(myBoxPrivate));
  const salt = [mine, theirBoxPublicEncoded].sort().join('|');

  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, 'meshchat-channel-v1', 32));
}

/** Encrypt a JSON-serialisable value. Layout: iv(12) | tag(16) | ciphertext. */
function seal(key, value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([
    cipher.update(JSON.stringify(value), 'utf8'),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

/** Decrypt a sealed buffer. Throws if the payload was tampered with. */
function open(key, buf) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  const plain = Buffer.concat([
    decipher.update(buf.subarray(28)),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString('utf8'));
}

// --- misc -----------------------------------------------------------------

function nonce() {
  return b64u(crypto.randomBytes(24));
}

function messageId() {
  return crypto.randomBytes(8).toString('hex');
}

module.exports = {
  b64u,
  unb64u,
  generateSigningPair,
  generateBoxPair,
  exportPublic,
  exportPrivate,
  importPublic,
  importPrivate,
  sign,
  verify,
  deriveMeshId,
  idMatchesKey,
  deriveChannelKey,
  seal,
  open,
  nonce,
  messageId,
};
