'use strict';

/**
 * The last thing standing between you and direct messaging.
 *
 * NAT was an addressing problem — with a shared IPv4 address there is simply no
 * address for anyone to send to, and no software can invent one. A firewall is a
 * different kind of obstacle entirely: the packets *can* be delivered, something
 * is just choosing to drop them. That's policy, and policy can be changed.
 *
 * Windows blocks unsolicited inbound connections by default, and hardest of all
 * on the "Public" network profile that most WiFi gets classified as. Adding one
 * allow rule for our port is what lets an IPv6 peer actually reach us.
 *
 * Adding a rule needs administrator rights, so this always goes through a UAC
 * prompt and only ever runs when the user explicitly asks for it.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const TCP_RULE = 'MeshChat TCP';
const UDP_RULE = 'MeshChat UDP';
const LAN_DISCOVERY_PORT = 47778;

function run(command, args, timeout = 15000) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, windowsHide: true }, (error, stdout, stderr) => {
      resolve({
        ok: !error,
        out: `${stdout || ''}${stderr || ''}`,
      });
    });
  });
}

async function ruleExists(name) {
  const { ok, out } = await run('netsh', [
    'advfirewall',
    'firewall',
    'show',
    'rule',
    `name=${name}`,
  ]);
  return ok && !/No rules match/i.test(out);
}

/** Which profile this network is on. "Public" is the most restrictive. */
async function currentProfile() {
  const { ok, out } = await run('netsh', ['advfirewall', 'show', 'currentprofile']);
  if (!ok) return null;
  const match = out.match(/^(\w+)\s+Profile Settings/im);
  return match ? match[1] : null;
}

/**
 * @returns {Promise<{supported:boolean, installed:boolean, profile:string|null}>}
 */
async function status() {
  if (process.platform !== 'win32') {
    // Other platforms either don't filter inbound by default or need the user's
    // own firewall tooling; nothing useful for us to claim here.
    return { supported: false, installed: true, profile: null };
  }

  const [tcp, udp, profile] = await Promise.all([
    ruleExists(TCP_RULE),
    ruleExists(UDP_RULE),
    currentProfile(),
  ]);

  return { supported: true, installed: tcp && udp, tcp, udp, profile };
}

/**
 * Add the inbound allow rules, prompting for administrator rights.
 *
 * The commands go into a temporary script rather than being crammed into a
 * nested PowerShell string — two layers of quoting around netsh arguments is a
 * reliable way to produce a rule that looks right and matches nothing.
 */
async function install(port) {
  if (process.platform !== 'win32') {
    return { ok: false, message: 'firewall automation is only wired up for Windows' };
  }

  const tcpPort = Number(port);
  if (!Number.isInteger(tcpPort) || tcpPort < 1 || tcpPort > 65535) {
    return { ok: false, message: `refusing to add a rule for port "${port}"` };
  }

  const script = path.join(os.tmpdir(), `meshchat-firewall-${Date.now()}.cmd`);
  fs.writeFileSync(
    script,
    [
      '@echo off',
      `netsh advfirewall firewall delete rule name="${TCP_RULE}" >nul 2>&1`,
      `netsh advfirewall firewall delete rule name="${UDP_RULE}" >nul 2>&1`,
      `netsh advfirewall firewall add rule name="${TCP_RULE}" dir=in action=allow protocol=TCP localport=${tcpPort} profile=any`,
      // Two UDP ports: the multicast beacon, and the app port itself for hole
      // punching. Windows is stateful and would normally let a punch back in as
      // the reply to our own, but only if we punched first — whoever starts
      // second would otherwise be dropped before the exchange ever begins.
      `netsh advfirewall firewall add rule name="${UDP_RULE}" dir=in action=allow protocol=UDP localport=${tcpPort},${LAN_DISCOVERY_PORT} profile=any`,
      '',
    ].join('\r\n'),
    'utf8'
  );

  try {
    const { ok, out } = await run(
      'powershell',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `Start-Process -FilePath cmd.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '/c','"${script}"'`,
      ],
      120000
    );

    if (!ok) {
      return {
        ok: false,
        message: /canceled|cancelled/i.test(out)
          ? 'you declined the administrator prompt, so nothing was changed'
          : `could not add the rule: ${out.trim().split('\n')[0] || 'unknown error'}`,
      };
    }
  } finally {
    try {
      fs.unlinkSync(script);
    } catch {
      /* temp file, it can linger */
    }
  }

  const after = await status();
  return after.installed
    ? { ok: true, message: `inbound allowed on TCP ${tcpPort} and UDP ${tcpPort}, ${LAN_DISCOVERY_PORT}` }
    : { ok: false, message: 'the rule did not appear afterwards — was the prompt declined?' };
}

module.exports = { status, install, TCP_RULE, UDP_RULE, LAN_DISCOVERY_PORT };
