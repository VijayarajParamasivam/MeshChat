'use strict';

/**
 * Works out *why* a machine has no global IPv6 address, which is the single
 * most useful thing to know when two peers can't reach each other.
 *
 * "No IPv6" has several causes that look identical from the app but need
 * completely different fixes:
 *
 *   - Windows has IPv6 switched off, on the adapter or via the registry.
 *   - The network offers no IPv6 at all: the router has it disabled, or the
 *     ISP never provisioned it.
 *   - A VPN is capturing traffic and not carrying IPv6.
 *
 * Everything here is read-only and stays on the local machine — no packets are
 * sent anywhere. The presence of a default IPv6 route is enough to tell whether
 * the network is offering IPv6, without contacting a third party to find out.
 */

const os = require('os');
const { execFile } = require('child_process');

const portal = require('./portal');

function run(command, args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, windowsHide: true }, (error, stdout, stderr) => {
      resolve({ ok: !error, out: `${stdout || ''}${stderr || ''}` });
    });
  });
}

/** Is there a default IPv6 route (::/0)? Without one, nothing can leave. */
async function hasDefaultRoute() {
  if (process.platform !== 'win32') return null;
  const { ok, out } = await run('netsh', ['interface', 'ipv6', 'show', 'route']);
  return ok ? /::\/0/.test(out) : null;
}

/** Adapters with the IPv6 stack bound, and whether any have it switched off. */
async function adapterBindings() {
  if (process.platform !== 'win32') return null;
  const { ok, out } = await run('powershell', [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    'Get-NetAdapterBinding -ComponentID ms_tcpip6 | ' +
      'Where-Object { $_.Name -notmatch "Loopback" } | ' +
      'ForEach-Object { "$($_.Name)=$($_.Enabled)" }',
  ], 20000);

  if (!ok) return null;

  const bindings = [];
  for (const row of out.split(/\r?\n/)) {
    const match = row.match(/^(.+)=(True|False)\s*$/i);
    if (match) bindings.push({ name: match[1].trim(), enabled: /true/i.test(match[2]) });
  }
  return bindings.length ? bindings : null;
}

/**
 * The registry switch that disables IPv6 system-wide. Absent means "default",
 * which is fully enabled. A non-zero value is a common leftover from old
 * "speed up your PC" advice and silently breaks all of this.
 */
async function disabledComponents() {
  if (process.platform !== 'win32') return null;
  const { ok, out } = await run('reg', [
    'query',
    'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
    '/v',
    'DisabledComponents',
  ]);

  if (!ok) return 0; // Not set at all — the healthy default.
  const match = out.match(/DisabledComponents\s+REG_DWORD\s+0x([0-9a-f]+)/i);
  return match ? parseInt(match[1], 16) : 0;
}

/**
 * @returns {Promise<{global:string[], verdict:string, advice:string[]}>}
 */
async function diagnose() {
  const { global, linkLocal, uniqueLocal } = portal.classifyIPv6();

  if (global.length) {
    // Having the address and being reachable at it are different things, and on
    // a mobile network you get the first without the second: the carrier hands
    // out a real global address, then drops every unsolicited packet aimed at
    // it. Claiming "IPv6 is working" here sends people hunting for a fault on a
    // machine that is configured perfectly.
    return {
      global,
      linkLocal,
      uniqueLocal,
      verdict: 'You have a globally routable IPv6 address.',
      advice: [
        '',
        'That is the hard part, but it does not guarantee friends can reach you.',
        'A router or carrier can still drop unsolicited inbound packets — mobile',
        'networks almost always do, which is why a phone hotspot gives you a',
        'perfect-looking address that nobody can connect to.',
        '',
        'To find out which you have, run /try <friend>:',
        '  "no reply"  — something upstream is dropping the packets.',
        '  "refused"   — they arrived, so the address is genuinely reachable.',
        '',
        'If both of you are being dropped, /punch has you both send at once,',
        'which gets through some firewalls that neither of you can dial through.',
      ],
    };
  }

  // The commonest confusion by far: ipconfig shows fe80:: on every machine
  // ever built, so people reasonably conclude they have IPv6 when they don't.
  const misleading = [];
  if (linkLocal.length) {
    misleading.push(
      '',
      `You do have ${linkLocal[0]} — but that is a link-local address.`,
      'Windows puts one on every network card whether or not the network carries',
      'IPv6 at all, and it never travels past your own cable. This is why ipconfig',
      'can look like you have IPv6 while nothing outside can reach you.'
    );
  }
  if (uniqueLocal.length) {
    misleading.push(
      '',
      `You also have ${uniqueLocal[0]}, a unique-local address — the IPv6`,
      'equivalent of 192.168.x.x. Private to your network and not routable.'
    );
  }
  misleading.push('', 'A real internet IPv6 address starts with 2 or 3.');

  const base = { global, linkLocal, uniqueLocal };

  const NETWORK_FIXES = [
    '',
    'This is your router or your ISP, not your PC. In order of likelihood:',
    '',
    '1. Router has IPv6 switched off. Open its admin page (usually',
    '   192.168.1.1 or 192.168.0.1), find Internet/WAN > IPv6, and enable it.',
    '   Connection type is normally DHCPv6 or SLAAC; for PPPoE links pick the',
    '   "PPPoE with IPv6" or dual-stack option. Reboot the router afterwards.',
    '',
    '2. ISP does not provide IPv6 on your plan. Common on some Indian wired',
    '   providers. Ask support directly: "is IPv6 enabled on my connection?"',
    '',
    '3. A mobile hotspot will get you an IPv6 address in seconds, and Indian',
    '   networks (Jio especially) are IPv6-first. But it is not a fix: carriers',
    '   drop unsolicited inbound, so you get an address nobody can connect to.',
    '   Useful for testing /punch, not for being reachable.',
    '',
    '4. If a VPN is running, turn it off and re-check — many block IPv6.',
  ];

  if (process.platform !== 'win32') {
    return {
      ...base,
      verdict: 'No internet-routable IPv6 address on this machine.',
      advice: [...misleading, ...NETWORK_FIXES],
    };
  }

  const [route, bindings, disabled] = await Promise.all([
    hasDefaultRoute(),
    adapterBindings(),
    disabledComponents(),
  ]);

  const offAdapters = (bindings || []).filter((b) => !b.enabled).map((b) => b.name);

  // Cause 1: Windows itself has IPv6 switched off.
  if (disabled) {
    return {
      ...base,
      verdict: `Windows has IPv6 disabled in the registry (DisabledComponents = 0x${disabled.toString(16)}).`,
      advice: [
        ...misleading,
        '',
        'This is usually left behind by old "optimise your PC" tweaks.',
        'Run PowerShell as administrator and clear it:',
        '  Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters" DisabledComponents 0',
        'Then reboot.',
      ],
    };
  }

  if (offAdapters.length) {
    return {
      ...base,
      verdict: `IPv6 is unticked on your network adapter (${offAdapters.join(', ')}).`,
      advice: [
        ...misleading,
        '',
        'Settings > Network > Change adapter options > right-click your adapter >',
        'Properties > tick "Internet Protocol Version 6 (TCP/IPv6)" > OK.',
        'Or in an admin PowerShell:',
        '  Enable-NetAdapterBinding -Name "Wi-Fi" -ComponentID ms_tcpip6',
      ],
    };
  }

  // Cause 2: Windows is fine, the network simply isn't offering IPv6.
  if (route === false || linkLocal.length || uniqueLocal.length) {
    return {
      ...base,
      verdict: 'Windows is fine — your network is not handing out internet IPv6.',
      advice: [...misleading, ...NETWORK_FIXES],
    };
  }

  return {
    ...base,
    verdict: 'No IPv6 addresses at all on this machine.',
    advice: [
      route === true
        ? 'There is an IPv6 route but no address, which suggests the router advertises'
        : 'The routing table could not be read, so this is a guess:',
      'IPv6 without actually handing out a prefix. Rebooting the router often fixes it.',
      ...NETWORK_FIXES,
    ],
  };
}

module.exports = { diagnose };
