'use strict';

/**
 * A contact card is the thing you copy and send to a friend over any channel you
 * like — WhatsApp, email, a sticky note. It carries who you are (Mesh ID and both
 * public keys) and where to reach you, signed so that a card altered in transit
 * is rejected.
 *
 * "Where" is a single onion address, which is a public key rather than a
 * location. The card is therefore the only thing you ever hand over, and it
 * reveals nothing about where you are — not your IP, not your ISP, not your
 * country. Handing it to the wrong person costs you an unwanted connection
 * attempt, not your address.
 *
 * This is the only "discovery" step in the app, and it happens out of band by
 * design. No directory, no lookup service, nothing to be taken offline.
 */

const c = require('./crypto');

const PREFIX = 'MESH1.';

/** Deterministic JSON so both ends sign and verify byte-identical input. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

/**
 * Build a signed card for the local identity.
 *
 * @param {object} profile  { id, name, sigil }
 * @param {object} keys     from identity.getKeys()
 * @param {Array}  endpoints [{ type: 'wan'|'lan', host, port }]
 */
function create(profile, keys, endpoints = []) {
  const payload = {
    v: 1,
    id: profile.id,
    sign: keys.signPublic,
    box: keys.boxPublic,
    name: profile.name,
    sigil: profile.sigil,
    endpoints: endpoints.map((e) => ({
      type: e.type,
      host: e.host,
      port: Number(e.port),
    })),
    ts: Date.now(),
  };

  const sig = c.sign(keys.signPrivate, canonical(payload));
  return PREFIX + c.b64u(JSON.stringify({ ...payload, sig }));
}

/**
 * Parse and fully verify a card. Throws with a readable reason on any problem,
 * because this runs on text a user pasted in from who-knows-where.
 */
function parse(code) {
  const trimmed = String(code || '').trim().replace(/\s+/g, '');
  if (!trimmed.startsWith(PREFIX)) {
    throw new Error('that does not look like a MeshChat code');
  }

  let card;
  try {
    card = JSON.parse(c.unb64u(trimmed.slice(PREFIX.length)).toString('utf8'));
  } catch {
    throw new Error('code is damaged — it was probably truncated when copied');
  }

  if (card.v !== 1) throw new Error(`unsupported card version ${card.v}`);
  if (!card.id || !card.sign || !card.box) throw new Error('code is missing fields');

  // The ID must be the hash of the signing key, so nobody can wear another ID.
  if (!c.idMatchesKey(card.id, card.sign)) {
    throw new Error('code is forged — the ID does not match its key');
  }

  const { sig, ...payload } = card;
  if (!c.verify(card.sign, canonical(payload), sig)) {
    throw new Error('signature check failed — the code was altered');
  }

  return {
    id: card.id,
    sign: card.sign,
    box: card.box,
    name: String(card.name || 'anon').slice(0, 24),
    sigil: String(card.sigil || '*').slice(0, 2),
    endpoints: Array.isArray(card.endpoints) ? card.endpoints : [],
    ts: card.ts,
  };
}

module.exports = { create, parse, canonical, PREFIX };
