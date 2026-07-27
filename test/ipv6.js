'use strict';

/**
 * Proves the IPv6 path: a peer dials this machine's *global* IPv6 address —
 * not loopback, not a LAN IPv4 address — and the handshake completes over it.
 *
 * IPv6 is the whole reason this app can be serverless in practice, so it gets
 * its own test. Skips cleanly where no global IPv6 exists (most CI runners),
 * because absence of IPv6 is an environment fact, not a defect in the code.
 */

const c = require('../src/core/crypto');
const card = require('../src/core/card');
const portal = require('../src/core/portal');
const transport = require('../src/core/transport');

const PORT = 47950;

let failures = 0;
const check = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? `  (${extra})` : ''}`);
  if (!ok) failures++;
};

function makePeer(name) {
  const signing = c.generateSigningPair();
  const box = c.generateBoxPair();
  const keys = {
    signPrivate: signing.privateKey,
    signPublic: c.exportPublic(signing.publicKey),
    boxPrivate: box.privateKey,
    boxPublic: c.exportPublic(box.publicKey),
  };
  return { profile: { id: c.deriveMeshId(keys.signPublic), name, sigil: name[0] }, keys };
}

(async () => {
  const addresses = portal.globalIPv6Addresses();

  if (!addresses.length) {
    console.log('SKIP  no global IPv6 address on this machine — nothing to test');
    process.exit(0);
  }

  const target = addresses[0];
  check('machine has a global IPv6 address', true, target);
  check('address is global unicast (2000::/3)', portal.isGlobalIPv6(target));
  check('link-local addresses are excluded', !addresses.some((a) => a.startsWith('fe80')));

  const a = makePeer('alice');
  const b = makePeer('bob');
  const ctxA = {
    identity: a.profile,
    keys: a.keys,
    cardCode: card.create(a.profile, a.keys, [{ type: 'ip6', host: target, port: PORT }]),
  };
  const ctxB = {
    identity: b.profile,
    keys: b.keys,
    cardCode: card.create(b.profile, b.keys, []),
  };

  check('card carries the ip6 endpoint', card.parse(ctxA.cardCode).endpoints[0].type === 'ip6');

  let server;
  const inbound = new Promise((resolve, reject) => {
    setTimeout(() => reject(new Error('no inbound link')), 10000);
    transport
      .listen(PORT, () => ctxA, (link) => {
        link.once('ready', () => resolve(link));
        link.once('failed', reject);
      })
      .then((s) => {
        server = s;
        check('listener is dual-stack', s.address().address === '::');
      })
      .catch(reject);
  });

  const dialed = await transport.dial(target, PORT, ctxB, a.profile.id, 8000);
  const served = await inbound;

  check('dialer reached the global IPv6 address', dialed.socket.remoteAddress === target);
  check(
    'server saw a real IPv6 peer, not a v4-mapped one',
    served.remoteAddress.includes(':') && !served.remoteAddress.startsWith('::ffff:'),
    served.remoteAddress
  );
  check('both sides completed the handshake', dialed.ready && served.ready);

  const echoed = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no echo')), 5000);
    served.on('message', (frame) => {
      if (frame.t === 'msg') served.send({ t: 'msg', id: 'r', body: `echo:${frame.body}` });
    });
    dialed.on('message', (frame) => {
      if (frame.t === 'msg') {
        clearTimeout(timer);
        resolve(frame.body);
      }
    });
    dialed.send({ t: 'msg', id: '1', body: 'direct over ipv6' });
  });
  check('encrypted round trip over IPv6', echoed === 'echo:direct over ipv6');

  dialed.close();
  served.close();
  if (server) server.close();

  console.log(failures ? `\n${failures} FAILURE(S)` : '\nIPv6 path confirmed');
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.error('harness failed:', err.message);
  process.exit(1);
});
