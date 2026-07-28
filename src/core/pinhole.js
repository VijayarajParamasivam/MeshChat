'use strict';

/**
 * Asking your own router to stop dropping inbound IPv6.
 *
 * `portal.js` solves the IPv4 problem, which is an *addressing* problem: behind
 * NAT there is no address of yours for anyone to send to, so it asks the router
 * to forward a port. IPv6 has no such problem — the address is already yours and
 * globally routable — and yet connections still fail, because almost every home
 * router ships a stateful IPv6 firewall that drops unsolicited inbound anyway.
 *
 * That is policy rather than impossibility, and there are two standard ways to
 * ask a router to change it:
 *
 *   - UPnP IGDv2 exposes WANIPv6FirewallControl with an `AddPinhole` action.
 *     This is the IPv6 counterpart of the AddPortMapping call portal.js makes,
 *     and it lives on the same device, found through the same SSDP search.
 *   - PCP (RFC 6887) is NAT-PMP's successor and, unlike NAT-PMP, was designed
 *     for IPv6 firewalls as well as NAT. It shares NAT-PMP's UDP port 5351,
 *     and routers that support it often prefer it.
 *
 * Both talk only to the gateway on your own network, so this keeps the promise
 * the rest of the project makes: nothing here contacts anybody's server.
 *
 * A phone hotspot has no such router to ask, and a carrier's firewall is far
 * upstream of anything that would answer. This fixes the fixable end — which is
 * enough, because only one of two peers needs to accept inbound for both to talk.
 */

const dgram = require('dgram');
const { execFile } = require('child_process');

const portal = require('./portal');

const IPV6_FIREWALL_SERVICES = ['urn:schemas-upnp-org:service:WANIPv6FirewallControl:1'];

const PCP_PORT = portal.NATPMP_PORT;
const PCP_VERSION = 2;
const PCP_OPCODE_MAP = 1;
const PCP_REQUEST_BYTES = 60;
const PCP_RESPONSE_BYTES = 60;
const PCP_SUCCESS = 0;

const PROTO_TCP = 6;
const PROTO_UDP = 17;

/** Routers cap pinhole leases hard; a day is the usual ceiling. */
const PINHOLE_LEASE_SECONDS = 3600;

const PCP_ERRORS = {
  1: 'router wants a different PCP version',
  2: 'router refused: not authorised (PCP is probably switched off)',
  3: 'router called the request malformed',
  4: 'router does not support mapping requests',
  5: 'router does not support that option',
  6: 'router called the option malformed',
  7: 'router has a network failure',
  8: 'router has no resources left for new mappings',
  9: 'router does not support that protocol',
  10: 'this machine has exceeded its mapping quota',
  11: 'router cannot provide the external address requested',
  12: 'router refused: address mismatch',
  13: 'too many ports requested at once',
};

// --- address helpers ------------------------------------------------------

/**
 * IPv6 text to the 16 raw bytes PCP wants. Node exposes no inet_pton, and the
 * addresses we hand this are ones we read off our own interfaces, so the job is
 * only to handle `::` compression and the trailing-IPv4 form.
 */
function ipv6ToBuffer(address) {
  let host = String(address).split('%')[0].trim();
  const buffer = Buffer.alloc(16);

  // A trailing dotted-quad (as in ::ffff:10.0.0.5) occupies the last four bytes.
  let v4 = null;
  const embedded = host.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (embedded) {
    v4 = embedded[1].split('.').map(Number);
    if (v4.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      throw new Error(`malformed IPv4 part in ${address}`);
    }
    host = `${host.slice(0, host.length - embedded[1].length)}0:0`;
  }

  const halves = host.split('::');
  if (halves.length > 2) throw new Error(`malformed IPv6 address ${address}`);

  // Splitting and dropping empties would quietly accept `2001:db8:::1`, so an
  // empty group anywhere other than at the `::` itself is an error.
  const splitGroups = (part) => {
    if (!part) return [];
    const groups = part.split(':');
    if (groups.some((group) => group === '')) {
      throw new Error(`malformed IPv6 address ${address}`);
    }
    return groups;
  };

  const head = splitGroups(halves[0]);
  const tail = halves.length === 2 ? splitGroups(halves[1]) : [];
  const zeros = halves.length === 2 ? 8 - head.length - tail.length : 0;

  if (zeros < 0) throw new Error(`too many groups in ${address}`);
  if (halves.length === 1 && head.length !== 8) {
    throw new Error(`expected 8 groups in ${address}`);
  }

  const groups = [...head, ...Array(zeros).fill('0'), ...tail];
  for (let i = 0; i < 8; i++) {
    const value = parseInt(groups[i], 16);
    if (Number.isNaN(value) || value < 0 || value > 0xffff) {
      throw new Error(`malformed group in ${address}`);
    }
    buffer.writeUInt16BE(value, i * 2);
  }

  if (v4) for (let i = 0; i < 4; i++) buffer[12 + i] = v4[i];

  return buffer;
}

function run(command, args, timeout = 6000) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, windowsHide: true }, (error, stdout, stderr) => {
      resolve({ ok: !error, out: `${stdout || ''}${stderr || ''}` });
    });
  });
}

/**
 * The IPv6 default router, which is where PCP requests have to go. There is no
 * discovery multicast for this — RFC 6887 simply says "your default gateway".
 */
async function ipv6Gateway() {
  if (process.platform === 'win32') {
    const { ok, out } = await run('netsh', ['interface', 'ipv6', 'show', 'route']);
    if (!ok) return null;
    // Publish  Type  Met  Prefix  Idx  Gateway/Interface Name
    const match = out.match(/^\S+\s+\S+\s+\d+\s+::\/0\s+(\d+)\s+(\S+)/m);
    if (!match) return null;
    const [, index, gateway] = match;
    // Link-local gateways are meaningless without the interface they live on.
    return gateway.startsWith('fe80:') ? `${gateway}%${index}` : gateway;
  }

  const { ok, out } = await run('ip', ['-6', 'route', 'show', 'default']);
  if (ok) {
    const match = out.match(/via\s+(\S+)(?:.*\bdev\s+(\S+))?/);
    if (match) return match[2] ? `${match[1]}%${match[2]}` : match[1];
  }

  return null;
}

// --- PCP ------------------------------------------------------------------

function pcpRequest(gateway, payload, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp6');
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
      if (err) reject(err);
      else resolve(value);
    };

    const timer = setTimeout(() => done(new Error('no PCP response')), timeout);

    socket.on('error', (err) => done(err));
    socket.on('message', (msg) => {
      if (msg.length < PCP_RESPONSE_BYTES) return done(new Error('short PCP reply'));
      done(null, msg);
    });

    socket.send(payload, PCP_PORT, gateway, (err) => {
      if (err) done(err);
    });
  });
}

/**
 * Build a PCP MAP request. On an IPv6 firewall the "mapping" is a pinhole:
 * internal and external port are the same and the router is being asked to stop
 * filtering rather than to translate anything.
 */
function buildMapRequest(clientIp, protocol, port, lifetime, nonce) {
  const packet = Buffer.alloc(PCP_REQUEST_BYTES);

  packet.writeUInt8(PCP_VERSION, 0);
  packet.writeUInt8(PCP_OPCODE_MAP, 1); // R bit clear = request
  packet.writeUInt16BE(0, 2); // reserved
  packet.writeUInt32BE(lifetime, 4);
  ipv6ToBuffer(clientIp).copy(packet, 8);

  nonce.copy(packet, 24);
  packet.writeUInt8(protocol, 36);
  // 37..39 reserved
  packet.writeUInt16BE(port, 40);
  packet.writeUInt16BE(port, 42); // suggested external port: the same one
  ipv6ToBuffer(clientIp).copy(packet, 44);

  return packet;
}

async function tryPcp(port, clientIp, gateway) {
  if (!gateway) return null;

  const nonce = Buffer.alloc(12);
  for (let i = 0; i < 12; i++) nonce[i] = Math.floor(Math.random() * 256);

  const opened = [];

  for (const protocol of [PROTO_TCP, PROTO_UDP]) {
    const request = buildMapRequest(clientIp, protocol, port, PINHOLE_LEASE_SECONDS, nonce);
    const reply = await pcpRequest(gateway, request);

    if (reply.readUInt8(0) !== PCP_VERSION) throw new Error('router replied in another PCP version');
    if (reply.readUInt8(1) !== (0x80 | PCP_OPCODE_MAP)) throw new Error('router replied to a different request');

    const result = reply.readUInt8(3);
    if (result !== PCP_SUCCESS) {
      throw new Error(PCP_ERRORS[result] || `router refused with PCP code ${result}`);
    }

    opened.push(protocol === PROTO_TCP ? 'tcp' : 'udp');
  }

  return { method: 'pcp', gateway, port, protocols: opened };
}

// --- UPnP IGDv2 -----------------------------------------------------------

async function tryUpnpPinhole(port, clientIp) {
  const locations = await portal.discoverGateways();

  for (const location of locations) {
    let service;
    try {
      service = await portal.readControlUrl(location, IPV6_FIREWALL_SERVICES);
    } catch {
      continue;
    }
    if (!service) continue;

    // Some routers advertise the service but have pinholes administratively
    // disabled. Asking first turns a silent no-op into something reportable.
    try {
      const body = await portal.soap(service.controlUrl, service.service, 'GetFirewallStatus');
      const allowed = body.match(/<InboundPinholeAllowed>([\s\S]*?)<\/InboundPinholeAllowed>/i);
      if (allowed && /^(0|false)$/i.test(allowed[1].trim())) {
        throw new Error('router has inbound pinholes disabled in its settings');
      }
    } catch (err) {
      if (/disabled in its settings/.test(err.message)) throw err;
      // Older firmware omits the action entirely; that is not a refusal.
    }

    const opened = [];
    for (const protocol of [PROTO_TCP, PROTO_UDP]) {
      await portal.soap(service.controlUrl, service.service, 'AddPinhole', {
        RemoteHost: '',
        RemotePort: 0, // any source — we cannot know who will dial us
        InternalClient: clientIp,
        InternalPort: port,
        Protocol: protocol,
        LeaseTime: PINHOLE_LEASE_SECONDS,
      });
      opened.push(protocol === PROTO_TCP ? 'tcp' : 'udp');
    }

    return { method: 'upnp-ipv6', controlUrl: service.controlUrl, service: service.service, port, protocols: opened };
  }

  return null;
}

// --- public API -----------------------------------------------------------

/**
 * Ask the router to let inbound IPv6 through on `port`.
 *
 * Always resolves. A router that refuses is the common case rather than an
 * error, and the app still works wherever the firewall is already permissive or
 * hole punching gets through.
 *
 * @returns {Promise<{ok:boolean, method:string|null, note:string}>}
 */
async function open(port, clientIp, { onLog = () => {} } = {}) {
  if (!clientIp) {
    return { ok: false, method: null, note: 'no global IPv6 address to open a pinhole for' };
  }

  onLog('pinhole: asking your router to allow inbound IPv6...');

  const reasons = [];

  try {
    const result = await tryUpnpPinhole(port, clientIp);
    if (result) {
      onLog(`pinhole: router opened ${result.protocols.join(' and ')} ${port} over UPnP`);
      return { ok: true, ...result, note: 'router is allowing inbound IPv6' };
    }
    reasons.push('router exposes no IPv6 firewall service over UPnP');
  } catch (err) {
    reasons.push(`UPnP: ${err.message}`);
  }

  try {
    const gateway = await ipv6Gateway();
    if (!gateway) {
      reasons.push('PCP: could not work out the IPv6 default gateway');
    } else {
      const result = await tryPcp(port, clientIp, gateway);
      if (result) {
        onLog(`pinhole: router opened ${result.protocols.join(' and ')} ${port} over PCP`);
        return { ok: true, ...result, note: 'router is allowing inbound IPv6' };
      }
    }
  } catch (err) {
    reasons.push(`PCP: ${err.message}`);
  }

  const note =
    'Router would not open an IPv6 pinhole. That is normal on a phone hotspot, ' +
    'where there is no router to ask. On a home router, look for IPv6 firewall ' +
    'settings in its admin page, or try /punch instead.';

  onLog(`pinhole: no luck — ${reasons[0] || 'no method available'}`);
  return { ok: false, method: null, reasons, note };
}

module.exports = {
  open,
  ipv6ToBuffer,
  ipv6Gateway,
  buildMapRequest,
  PINHOLE_LEASE_SECONDS,
  PROTO_TCP,
  PROTO_UDP,
};
