'use strict';

/**
 * Getting a reachable address without anybody's server.
 *
 * The problem: your machine has no address on the internet. The router owns the
 * single public IP and drops unsolicited inbound packets because no rule tells it
 * which device inside the house they belong to. That is NAT, and it is the only
 * reason peer-to-peer chat normally needs a middleman.
 *
 * The fix: ask your own router to open the door. UPnP and NAT-PMP are protocols
 * that exist precisely so a program on the LAN can request a port forward and ask
 * what the public IP is. The router is your hardware on your network, so nothing
 * here contacts a third party — and because the router reports the external IP
 * itself, no STUN server is needed either.
 *
 * Order of attempts: UPnP, then NAT-PMP, then give up and run LAN-only.
 */

const dgram = require('dgram');
const http = require('http');
const os = require('os');
const { execFileSync } = require('child_process');
const { URL } = require('url');

const SSDP_ADDR = '239.255.255.250';
const SSDP_PORT = 1900;
const NATPMP_PORT = 5351;
const LEASE_SECONDS = 3600;
const DESCRIPTION = 'MeshChat';

const WAN_SERVICES = [
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANIPConnection:2',
  'urn:schemas-upnp-org:service:WANPPPConnection:1',
];

let active = null;
let renewTimer = null;

// --- local network facts --------------------------------------------------

/** Our IPv4 address on the LAN. */
function lanAddress() {
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const addr of addresses || []) {
      if (addr.family === 'IPv4' && !addr.internal) return addr.address;
    }
  }
  return '127.0.0.1';
}

/**
 * Best guess at the router's address. Home routers are almost always .1 on the
 * subnet; NAT-PMP needs a target and SSDP tells us the real one when it works.
 */
function gatewayGuess(lanIp = lanAddress()) {
  const parts = lanIp.split('.');
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.${parts[2]}.1`;
}

function isPrivate(ip) {
  if (!ip) return true;
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

/** Carrier-grade NAT: the ISP itself is NATing you, so inbound is impossible. */
function isCgnat(ip) {
  if (!ip) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 100 && b >= 64 && b <= 127;
}

// --- IPv6 -----------------------------------------------------------------

/**
 * Is this a globally routable IPv6 address?
 *
 * Global unicast is 2000::/3 — the high three bits are 001. Everything else is
 * either link-local (fe80::/10, this-cable-only), unique-local (fc00::/7, a
 * private range like 192.168 but for v6), or loopback. Only global addresses
 * can be dialled from the internet.
 */
function isGlobalIPv6(address) {
  if (!address) return false;
  const head = parseInt(address.split(':')[0] || '0', 16);
  return (head & 0xe000) === 0x2000;
}

/** Node has reported `family` as both 'IPv6' and 6 across versions. */
function isIPv6Entry(addr) {
  return addr.family === 'IPv6' || addr.family === 6;
}

/**
 * Sort every IPv6 address on this machine into what it's actually good for.
 *
 * This matters because `ipconfig` always shows a link-local `fe80::` address on
 * every machine ever made, whether or not the network carries IPv6 at all. It
 * looks exactly like having IPv6, so "my ipconfig shows IPv6 but the app says
 * none" is the expected confusion rather than a bug — only the `global` list can
 * be reached from the internet.
 */
function classifyIPv6() {
  const global = [];
  const linkLocal = [];
  const uniqueLocal = [];

  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const addr of addresses || []) {
      if (!isIPv6Entry(addr) || addr.internal) continue;

      const host = addr.address.split('%')[0];
      const head = parseInt(host.split(':')[0] || '0', 16);

      let bucket = null;
      if (isGlobalIPv6(host)) bucket = global;
      else if ((head & 0xffc0) === 0xfe80) bucket = linkLocal;
      else if ((head & 0xfe00) === 0xfc00) bucket = uniqueLocal;

      if (bucket && !bucket.includes(host)) bucket.push(host);
    }
  }

  return { global, linkLocal, uniqueLocal };
}

/** Every globally routable IPv6 address on this machine. */
function globalIPv6Addresses() {
  return classifyIPv6().global;
}

/**
 * Rank our IPv6 addresses so the most useful one leads the contact card.
 *
 * Windows keeps several at once. A stable "Public" address outlives a rotating
 * "Temporary" privacy one, and when the ISP changes your prefix the old
 * addresses linger in a "Deprecated" state — still assigned, but on their way
 * out and quite likely to refuse connections. Order is therefore:
 * preferred+stable, preferred+temporary, then anything deprecated.
 *
 * Best effort only — on any parsing failure the original order is kept.
 */
function orderIPv6Stable(addresses) {
  if (process.platform !== 'win32' || addresses.length < 2) return addresses;

  try {
    const output = execFileSync(
      'netsh',
      ['interface', 'ipv6', 'show', 'addresses'],
      { encoding: 'utf8', timeout: 4000, windowsHide: true }
    );

    // Rows look like:
    //   Public     Preferred     1h59m28s   1h59m28s 2409:40f4:214d:95ae:8927:...
    //   Addr Type  DAD State     Valid Life Pref Life Address
    const rank = new Map();
    for (const row of output.split(/\r?\n/)) {
      const match = row.match(
        /^(Public|Temporary|Other)\s+(Preferred|Deprecated|\w+)\s+\S+\s+\S+\s+([0-9a-fA-F:]+)/i
      );
      if (!match) continue;

      const [, type, dadState, host] = match;
      const deprecated = /^deprecated$/i.test(dadState);
      const temporary = /^temporary$/i.test(type);
      rank.set(host.toLowerCase(), (deprecated ? 2 : 0) + (temporary ? 1 : 0));
    }

    // Unrecognised addresses sort between "preferred" and "deprecated" rather
    // than being trusted or discarded outright.
    return [...addresses].sort(
      (a, b) => (rank.get(a.toLowerCase()) ?? 1.5) - (rank.get(b.toLowerCase()) ?? 1.5)
    );
  } catch {
    return addresses;
  }
}

// --- tiny HTTP helpers ----------------------------------------------------

function request(options, body, timeout = 4000) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });

    req.setTimeout(timeout, () => req.destroy(new Error('timed out')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// --- UPnP -----------------------------------------------------------------

/**
 * Shout on the local multicast group and see which routers answer. Every reply
 * carries a LOCATION header pointing at the device's description document.
 */
function discoverGateways(timeout = 2500) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const locations = new Set();

    const finish = () => {
      try {
        socket.close();
      } catch {
        /* already closed */
      }
      resolve([...locations]);
    };

    socket.on('error', finish);

    socket.on('message', (msg) => {
      const text = msg.toString('utf8');
      const match = text.match(/^LOCATION:\s*(.+)$/im);
      if (match) locations.add(match[1].trim());
    });

    socket.bind(() => {
      const search = (target) =>
        Buffer.from(
          'M-SEARCH * HTTP/1.1\r\n' +
            `HOST: ${SSDP_ADDR}:${SSDP_PORT}\r\n` +
            'MAN: "ssdp:discover"\r\n' +
            'MX: 2\r\n' +
            `ST: ${target}\r\n\r\n`
        );

      const targets = [
        'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        ...WAN_SERVICES,
      ];

      for (const target of targets) {
        socket.send(search(target), SSDP_PORT, SSDP_ADDR, () => {});
      }

      setTimeout(finish, timeout);
    });
  });
}

/**
 * Pull the device description and find the control URL of whichever WAN
 * connection service this router exposes.
 */
async function readControlUrl(location) {
  const url = new URL(location);
  const res = await request({
    method: 'GET',
    host: url.hostname,
    port: url.port || 80,
    path: url.pathname + url.search,
  });

  if (res.status !== 200) return null;

  // Good enough XML handling for a document with this rigid a shape.
  const blocks = res.body.match(/<service>[\s\S]*?<\/service>/gi) || [];

  for (const service of WAN_SERVICES) {
    for (const block of blocks) {
      if (!block.includes(service)) continue;
      const control = block.match(/<controlURL>([\s\S]*?)<\/controlURL>/i);
      if (!control) continue;
      return {
        service,
        controlUrl: new URL(control[1].trim(), location).toString(),
      };
    }
  }

  return null;
}

async function soap(controlUrl, service, action, args = {}) {
  const url = new URL(controlUrl);
  const params = Object.entries(args)
    .map(([k, v]) => `<${k}>${v}</${k}>`)
    .join('');

  const envelope =
    '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>' +
    `<u:${action} xmlns:u="${service}">${params}</u:${action}>` +
    '</s:Body></s:Envelope>';

  const res = await request(
    {
      method: 'POST',
      host: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'text/xml; charset="utf-8"',
        SOAPAction: `"${service}#${action}"`,
        'Content-Length': Buffer.byteLength(envelope),
      },
    },
    envelope
  );

  if (res.status !== 200) {
    const reason = res.body.match(/<errorDescription>([\s\S]*?)<\/errorDescription>/i);
    throw new Error(reason ? reason[1] : `router refused ${action} (${res.status})`);
  }

  return res.body;
}

async function tryUpnp(port, lanIp) {
  const locations = await discoverGateways();

  for (const location of locations) {
    let gateway;
    try {
      gateway = await readControlUrl(location);
    } catch {
      continue;
    }
    if (!gateway) continue;

    const { controlUrl, service } = gateway;

    const mapping = {
      NewRemoteHost: '',
      NewExternalPort: port,
      NewProtocol: 'TCP',
      NewInternalPort: port,
      NewInternalClient: lanIp,
      NewEnabled: 1,
      NewPortMappingDescription: DESCRIPTION,
      NewLeaseDuration: LEASE_SECONDS,
    };

    try {
      await soap(controlUrl, service, 'AddPortMapping', mapping);
    } catch {
      // Plenty of routers reject any lease that isn't permanent.
      try {
        await soap(controlUrl, service, 'AddPortMapping', {
          ...mapping,
          NewLeaseDuration: 0,
        });
      } catch {
        continue;
      }
    }

    let externalIp = null;
    try {
      const body = await soap(controlUrl, service, 'GetExternalIPAddress');
      const found = body.match(/<NewExternalIPAddress>([\s\S]*?)<\/NewExternalIPAddress>/i);
      externalIp = found ? found[1].trim() : null;
    } catch {
      /* mapping still stands even if the query failed */
    }

    return { method: 'upnp', controlUrl, service, externalIp, externalPort: port };
  }

  return null;
}

async function removeUpnp(portal) {
  await soap(portal.controlUrl, portal.service, 'DeletePortMapping', {
    NewRemoteHost: '',
    NewExternalPort: portal.externalPort,
    NewProtocol: 'TCP',
  });
}

// --- NAT-PMP --------------------------------------------------------------

function natpmpRequest(gateway, payload, expectedLength, timeout = 1500) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const done = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        /* already closed */
      }
      err ? reject(err) : resolve(value);
    };

    const timer = setTimeout(() => done(new Error('no NAT-PMP response')), timeout);

    socket.on('error', (err) => done(err));
    socket.on('message', (msg) => {
      if (msg.length < expectedLength) return done(new Error('short NAT-PMP reply'));
      if (msg.readUInt16BE(2) !== 0) return done(new Error('router refused NAT-PMP'));
      done(null, msg);
    });

    socket.send(payload, NATPMP_PORT, gateway, (err) => {
      if (err) done(err);
    });
  });
}

async function tryNatpmp(port, gateway) {
  if (!gateway) return null;

  try {
    // Opcode 0: what is my external address?
    const info = await natpmpRequest(gateway, Buffer.from([0, 0]), 12);
    const externalIp = [info[8], info[9], info[10], info[11]].join('.');

    // Opcode 2: map an external TCP port to our internal one.
    const map = Buffer.alloc(12);
    map.writeUInt8(0, 0);
    map.writeUInt8(2, 1);
    map.writeUInt16BE(0, 2);
    map.writeUInt16BE(port, 4);
    map.writeUInt16BE(port, 6);
    map.writeUInt32BE(LEASE_SECONDS, 8);

    const reply = await natpmpRequest(gateway, map, 16);

    return {
      method: 'natpmp',
      gateway,
      externalIp,
      externalPort: reply.readUInt16BE(10),
    };
  } catch {
    return null;
  }
}

async function removeNatpmp(portal) {
  // Same mapping request with a lifetime of zero tears it down.
  const map = Buffer.alloc(12);
  map.writeUInt8(0, 0);
  map.writeUInt8(2, 1);
  map.writeUInt16BE(0, 2);
  map.writeUInt16BE(portal.externalPort, 4);
  map.writeUInt16BE(0, 6);
  map.writeUInt32BE(0, 8);
  await natpmpRequest(portal.gateway, map, 16);
}

// --- public API -----------------------------------------------------------

/**
 * Try to become reachable from the internet. Always resolves — if every method
 * fails we simply report LAN-only rather than treating it as an error, since
 * same-network chat still works perfectly.
 */
async function open(port, { onLog = () => {} } = {}) {
  const lanIp = lanAddress();
  const gateway = gatewayGuess(lanIp);

  // IPv6 first, because when it's available it makes the rest irrelevant:
  // a global IPv6 address is dialable as-is, with no router negotiation at all.
  const kinds = classifyIPv6();
  const ip6 = orderIPv6Stable(kinds.global);
  if (ip6.length) {
    onLog(`portal: public IPv6 found (${ip6[0]}) — no NAT to get around`);
  } else if (kinds.linkLocal.length || kinds.uniqueLocal.length) {
    onLog('portal: IPv6 exists here but none of it is internet-routable');
  }

  onLog('portal: asking your router for an IPv4 way in...');

  let result = null;
  try {
    result = await tryUpnp(port, lanIp);
  } catch {
    result = null;
  }

  if (!result) {
    onLog('portal: no UPnP, trying NAT-PMP...');
    result = await tryNatpmp(port, gateway);
  }

  const ipv4 = result || {
    method: 'lan-only',
    externalIp: null,
    externalPort: null,
  };

  const cgnat = isCgnat(ipv4.externalIp);
  const doubleNat = !cgnat && Boolean(ipv4.externalIp) && isPrivate(ipv4.externalIp);
  const ipv4Reachable = Boolean(ipv4.externalIp) && !cgnat && !doubleNat;

  let ipv4Note;
  if (!result) {
    ipv4Note =
      'IPv4: the router would not open a port (UPnP is often off by default). ' +
      `To use IPv4 too, enable UPnP or forward TCP ${port} to ${lanIp} by hand.`;
  } else if (cgnat) {
    ipv4Note =
      'IPv4: your ISP uses carrier-grade NAT, so no IPv4 address of yours exists ' +
      'for anyone to dial. This is an ISP limit that no software can work around.';
  } else if (doubleNat) {
    ipv4Note =
      `IPv4: the router reports a private address (${ipv4.externalIp}), so there is ` +
      'a second router above it that would also need to forward the port.';
  } else {
    ipv4Note = 'IPv4: reachable through the router.';
  }

  const note = ip6.length
    ? 'You have a public IPv6 address, so there is no NAT between you and the ' +
      'internet. Friends who also have IPv6 can dial you directly — provided the ' +
      'firewall allows it (/firewall). ' +
      ipv4Note
    : ipv4Reachable
      ? 'Reachable over IPv4. Friends can dial you directly.'
      : `No public address on this network. Same-WiFi chat works. ${ipv4Note}`;

  active = {
    ...ipv4,
    ip6,
    ip6LinkLocal: kinds.linkLocal,
    ip6UniqueLocal: kinds.uniqueLocal,
    ip6Reachable: ip6.length > 0,
    ipv4Reachable,
    lanIp,
    lanPort: port,
    reachable: ip6.length > 0 || ipv4Reachable,
    cgnat,
    ipv4Note,
    note,
  };

  // Leases expire; renew well before they do.
  clearInterval(renewTimer);
  renewTimer = setInterval(() => {
    const mapped = active?.lanPort;
    if (!mapped) return;
    if (active.method === 'upnp') {
      tryUpnp(mapped, active.lanIp).catch(() => {});
    } else if (active.method === 'natpmp') {
      tryNatpmp(mapped, active.gateway).catch(() => {});
    }
  }, (LEASE_SECONDS / 2) * 1000);

  return active;
}

/** Hand the port back to the router on the way out. */
async function close() {
  clearInterval(renewTimer);
  renewTimer = null;
  if (!active) return;

  try {
    if (active.method === 'upnp') await removeUpnp(active);
    else if (active.method === 'natpmp') await removeNatpmp(active);
  } catch {
    // The lease expires on its own; nothing worth failing shutdown over.
  }
  active = null;
}

function status() {
  return active;
}

module.exports = {
  open,
  close,
  status,
  lanAddress,
  gatewayGuess,
  isPrivate,
  isGlobalIPv6,
  globalIPv6Addresses,
  classifyIPv6,
};
