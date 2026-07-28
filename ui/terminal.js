'use strict';

/**
 * The whole interface: a log, a prompt, and a command parser. Anything that
 * isn't a slash command is a message to whoever you're currently talking to.
 */

const logEl = document.getElementById('log');
const typedEl = document.getElementById('typed');
const symEl = document.getElementById('sym');
const captureEl = document.getElementById('capture');
const screenEl = document.getElementById('screen');

const state = {
  mode: 'boot', // boot | handle | ready
  profile: null,
  active: null, // { id, name }
  history: [],
  historyIndex: 0,
};

// --- output ---------------------------------------------------------------

function line(text = '', cls = 'sys') {
  const el = document.createElement('div');
  el.className = `line ${cls}`;
  el.textContent = text;
  logEl.appendChild(el);
  screenEl.scrollTop = screenEl.scrollHeight;
  return el;
}

function sys(text) {
  line(`> ${text}`, 'sys');
}

function err(text) {
  line(`! ${text}`, 'err');
}

function clock(ts) {
  return new Date(ts).toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
  });
}

const MARKS = { queued: ' [~]', sent: ' [>]', delivered: ' [ok]' };

function paintMessage(el, name, message) {
  const mark = message.mine ? MARKS[message.state] || '' : '';
  el.textContent = `[${clock(message.ts)}] <${name}> ${message.body}${mark}`;
}

function showMessage(name, message) {
  const el = line('', message.mine ? 'me' : 'them');
  el.id = `m-${message.id}`;
  el.dataset.name = name;
  el.dataset.state = message.state;
  paintMessage(el, name, message);
  return el;
}

function banner() {
  line('  __  __        _    ___ _         _   ', 'banner');
  line(' |  \\/  |___ __| |_ / __| |_  __ _| |_ ', 'banner');
  line(' | |\\/| / -_|_-< \' \\ (__| \' \\/ _` |  _|', 'banner');
  line(' |_|  |_\\___/__/_||_\\___|_||_\\__,_|\\__|', 'banner');
  line('');
  line(' no servers. no relays. no middlemen.', 'hot');
  line(' your device dials their device, and that is the whole network.', 'sys');
  line('');
}

// --- engine calls ---------------------------------------------------------

async function call(method, payload) {
  return window.mesh.call(method, payload);
}

function promptSymbol() {
  symEl.textContent = state.active ? `${state.active.name}>` : '>';
}

async function enterReady(boot) {
  state.mode = 'ready';
  state.profile = boot.profile;

  sys(`handle   ${boot.profile.sigil} ${boot.profile.name}`);
  sys(`mesh id  ${boot.profile.id}`);
  if (boot.instance) sys(`instance ${boot.instance} (separate identity for testing)`);

  if (boot.portal) describePortal(boot.portal);
  warnAboutFirewall(boot.firewall, boot.portal);

  const friends = boot.friends?.length ? boot.friends : await call('friends');
  if (friends.length) {
    sys(`${friends.length} friend(s) known — /friends to list, /chat <name> to talk`);
  } else {
    sys('no friends yet. run /card, send that code to someone, and have them /add it.');
  }

  line('');
  sys('/help for commands');
  line('');
  promptSymbol();
}

/** IPv6 literals need brackets to be readable next to a port. */
function addr(host, port) {
  return String(host).includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

function describePortal(portal) {
  if (!portal) return;

  if (portal.ip6Reachable) {
    sys(`portal   public IPv6 — ${portal.ip6[0]}`);
    line('  no NAT between you and the internet. this is a genuinely direct path.', 'sys');
  } else if (portal.ipv4Reachable) {
    sys(`portal   ${portal.method} — ${portal.externalIp}:${portal.externalPort}`);
  } else {
    sys('portal   no public address — same-network chat only');
    line(`  ${portal.ipv4Note || portal.note}`, 'sys');
  }
}

function warnAboutFirewall(firewall, portal) {
  if (!firewall?.supported || firewall.installed) return;
  if (!portal?.reachable) return;

  line('');
  line('! you have a direct path to the internet, but windows is blocking inbound.', 'err');
  line(
    `  this network is on the "${firewall.profile}" profile, which drops unsolicited`,
    'err'
  );
  line('  connections by default. run /firewall to allow them.', 'err');
}

// --- commands -------------------------------------------------------------

const HELP = [
  '  /help              this list',
  '  /who               your handle, id and data directory',
  '  /me <name>         change your display name',
  '  /sigil <char>      change your one-character sigil',
  '',
  '  /card              print your contact code',
  '  /copy              copy your contact code to the clipboard',
  '  /add <code>        add a friend from their code (or a /nearby mesh id)',
  '  /paste             add a friend from a code already on your clipboard',
  '  /forget <who>      remove a friend',
  '',
  '  /friends           who you know and who is online',
  '  /nearby            meshchat instances seen on this network',
  '  /chat <who>        open a conversation',
  '  /leave             close the conversation',
  '',
  '  /net               connection diagnostics',
  '  /try <who>         force a connection attempt and show why it fails',
  '  /punch <who>       hole-punch to a friend nobody can dial (both must be online)',
  '  /ipv6              why this machine has no IPv6, and how to fix it',
  '  /firewall          allow inbound connections (asks for admin)',
  '  /export            write an identity backup file',
  '  /import <path>     restore an identity backup',
  '  /clear             wipe the screen',
  '  /quit              exit',
  '',
  '  anything else is sent to whoever you are chatting with.',
];

async function openChat(query) {
  const found = await call('resolve', query);
  if (!found) {
    err(`no single match for "${query}" — try /friends`);
    return;
  }

  state.active = found;
  promptSymbol();

  const history = await call('history', { peerId: found.id, limit: 40 });
  line('');
  sys(`--- ${found.name} (${found.id}) ---`);
  if (!history.length) sys('no messages yet');
  for (const message of history) {
    showMessage(message.mine ? 'me' : found.name, message);
  }
  line('');
}

async function runCommand(raw) {
  const [command, ...rest] = raw.slice(1).split(/\s+/);
  const arg = raw.slice(1).slice(command.length).trim();

  switch (command.toLowerCase()) {
    case 'help':
      line('');
      for (const row of HELP) line(row, 'sys');
      line('');
      return;

    case 'who': {
      const boot = await call('boot');
      sys(`${boot.profile.sigil} ${boot.profile.name}  ${boot.profile.id}`);
      sys(`data ${boot.dataDir}`);
      return;
    }

    case 'me': {
      if (!arg) return err('usage: /me <name>');
      const profile = await call('setProfile', { name: arg });
      state.profile = profile;
      sys(`you are now ${profile.name}`);
      return;
    }

    case 'sigil': {
      if (!arg) return err('usage: /sigil <char>');
      const profile = await call('setProfile', { sigil: arg });
      state.profile = profile;
      sys(`sigil set to ${profile.sigil}`);
      return;
    }

    case 'card': {
      const code = await call('card');
      line('');
      sys('send this to a friend over any channel you like:');
      line(code, 'hot');
      line('');
      sys('they run /add <code>. only one of you needs to do it.');
      return;
    }

    case 'copy': {
      await call('copy', await call('card'));
      sys('contact code copied to clipboard');
      return;
    }

    case 'add': {
      if (!arg) return err('usage: /add <code or mesh id>');
      sys('verifying and dialling...');
      const friend = await call('addFriend', arg);
      sys(`${friend.name} added — /chat ${friend.name}`);
      return;
    }

    case 'paste': {
      const text = await call('paste');
      if (!text) return err('clipboard is empty');
      sys('verifying and dialling...');
      const friend = await call('addFriend', text);
      sys(`${friend.name} added — /chat ${friend.name}`);
      return;
    }

    case 'forget': {
      if (!arg) return err('usage: /forget <who>');
      const found = await call('resolve', arg);
      if (!found) return err(`no single match for "${arg}"`);
      await call('removeFriend', found.id);
      if (state.active?.id === found.id) state.active = null;
      promptSymbol();
      sys(`forgot ${found.name}`);
      return;
    }

    case 'friends': {
      const friends = await call('friends');
      if (!friends.length) return sys('nobody yet. /card to get your code.');
      line('');
      for (const friend of friends) {
        line(
          `  ${friend.online ? '[online] ' : '[   off] '}${friend.sigil} ${friend.name.padEnd(14)} ${friend.id}`,
          friend.online ? 'hot' : 'sys'
        );
      }
      line('');
      return;
    }

    case 'nearby': {
      const peers = await call('nearby');
      if (!peers.length) return sys('nothing else on this network right now');
      line('');
      for (const peer of peers) {
        line(
          `  ${peer.known ? '[known]  ' : '[new]    '}${peer.id}  ${peer.host}:${peer.port}`,
          'sys'
        );
      }
      line('');
      sys('/add <mesh id> to connect to one of these');
      return;
    }

    case 'chat': {
      if (!arg) return err('usage: /chat <name or mesh id>');
      await openChat(arg);
      return;
    }

    case 'leave':
      state.active = null;
      promptSymbol();
      sys('conversation closed');
      return;

    case 'net': {
      const net = await call('net');
      if (!net) return err('engine not running');
      const fw = net.firewall || {};
      line('');

      if (net.ip6?.length) {
        sys(`ipv6         ${addr(net.ip6[0], net.port)}`);
        for (const extra of net.ip6.slice(1)) line(`             ${addr(extra, net.port)}`, 'sys');
        line('             public and routable — nothing is translating it', 'sys');
        // Having the address is only half of it; the router still has to be
        // willing to let strangers in on it.
        if (net.ip6Pinhole) {
          line(`             router is allowing inbound (${net.ip6PinholeMethod})`, 'sys');
        } else {
          line('             but the router was not willing to open a pinhole,', 'sys');
          line('             so inbound may still be dropped. /punch works around it.', 'sys');
        }
      } else {
        sys('ipv6         none that the internet can reach');
        // ipconfig shows these on every machine alive, so spell out why they
        // don't count rather than leaving a bare "none" to argue with.
        for (const host of net.ip6LinkLocal || []) {
          line(`             ${host}  link-local — never leaves your cable`, 'sys');
        }
        for (const host of net.ip6UniqueLocal || []) {
          line(`             ${host}  private range — like 192.168, not routable`, 'sys');
        }
        if ((net.ip6LinkLocal || []).length || (net.ip6UniqueLocal || []).length) {
          line('             a real one starts with 2 or 3. run /ipv6 for why.', 'sys');
        }
      }

      sys(`ipv4         ${net.lanIp}:${net.lanPort}  (${net.method})`);
      if (net.externalIp) sys(`ipv4 public  ${net.externalIp}:${net.externalPort}`);
      else if (net.cgnat) line('             carrier-grade NAT — no ipv4 address is yours', 'sys');

      sys(
        `firewall     ${
          !fw.supported
            ? 'not managed here'
            : fw.installed
              ? 'inbound allowed'
              : `blocking inbound (${fw.profile} profile)`
        }`
      );

      line('');
      const openable = !fw.supported || fw.installed;
      // A global IPv6 address is not the same as being reachable at it. Saying
      // "friends can dial you" on the strength of the address alone contradicts
      // the pinhole warning printed a few lines above, and it is exactly the
      // conflation that sends people hunting for a fault on a healthy machine.
      const confirmed = net.ipv4Reachable || (net.ip6?.length && net.ip6Pinhole);

      if (!openable) {
        line('  you have a direct path, but the firewall is shut. run /firewall.', 'err');
      } else if (confirmed) {
        line('  friends can dial you directly right now.', 'hot');
      } else if (net.ip6?.length) {
        line('  you have a public address, but nothing has confirmed inbound', 'sys');
        line('  actually reaches it — your router or carrier may still drop it.', 'sys');
        line('  run /try <friend> to find out which. /punch works around it.', 'sys');
      } else {
        line('  no public address here, so only same-WiFi chat works.', 'err');
        line(`  ${net.ipv4Note || ''}`, 'sys');
      }
      line('');
      return;
    }

    case 'try': {
      if (!arg) return err('usage: /try <who>');
      sys(`dialling ${arg}...`);
      const result = await call('probe', arg);

      if (result.alreadyOnline) return sys(`${result.name} is already connected`);

      line('');
      sys(`addresses on record for ${result.name}:`);
      if (!result.endpoints.length) line('  (none — their card had no reachable address)', 'err');
      for (const e of result.endpoints) {
        const host = String(e.host).includes(':') ? `[${e.host}]:${e.port}` : `${e.host}:${e.port}`;
        line(`  ${e.type.padEnd(4)} ${host}`, 'sys');
      }

      line('');
      if (result.ok) {
        line(`  connected to ${result.name}.`, 'hot');
      } else {
        line('  every address failed:', 'err');
        for (const reason of result.reasons) line(`  ${reason}`, 'err');
        line('', 'sys');
        line('  if they have no ipv6 and you do, there is no shared path at all.', 'sys');
        line('  have them run /ipv6 on their machine.', 'sys');
        line('  if you both have ipv6, try /punch — it works when neither side', 'sys');
        line('  can be dialled, but you must both be online at the same moment.', 'sys');
      }
      line('');
      return;
    }

    case 'punch': {
      if (!arg) return err('usage: /punch <who>');

      line('');
      sys('hole punching works by both machines sending at the same instant, so');
      sys('each firewall sees the reply to something its own side already sent.');
      sys('that only works if they have meshchat open right now — tell them to');
      sys('run /punch back at you before you continue.');
      line('');

      const result = await call('punch', arg);
      if (result.alreadyOnline) return sys(`${result.name} is already connected`);

      sys(`waiting for the shared window (${(result.windowMs / 1000).toFixed(1)}s), then firing...`);
      line('');

      if (result.ok) {
        line(`  connected to ${result.name} — the punch got through.`, 'hot');
      } else {
        line('  punch failed:', 'err');
        for (const reason of result.reasons) line(`  ${reason}`, 'err');
        line('', 'sys');
        line('  if they were definitely running, one of the two networks drops', 'sys');
        line('  reciprocal udp. mobile carriers usually do. at that point one end', 'sys');
        line('  needs a connection that accepts inbound — wired broadband with an', 'sys');
        line('  ipv6 pinhole open on this port.', 'sys');
      }
      line('');
      return;
    }

    case 'ipv6': {
      const report = await call('ipv6');
      line('');
      if (report.global.length) {
        for (const address of report.global) sys(`ipv6  ${address}`);
      } else {
        sys('ipv6  none');
      }
      line('');
      line(`  ${report.verdict}`, report.global.length ? 'hot' : 'err');
      if (report.advice.length) line('');
      for (const row of report.advice) line(`  ${row}`, 'sys');
      line('');
      return;
    }

    case 'firewall': {
      const { firewall: fw } = await call('net');
      if (!fw.supported) return sys('nothing to configure on this platform');
      if (fw.installed) return sys('inbound is already allowed — nothing to do');

      sys('asking windows for permission — accept the administrator prompt...');
      const result = await call('openFirewall');
      if (!result.ok) return err(result.message);

      sys(result.message);
      sys('friends can now reach you. run /net to confirm.');
      return;
    }

    case 'export': {
      const file = await call('exportIdentity');
      sys(`identity written to ${file}`);
      line('  anyone holding that file can be you. guard it.', 'err');
      return;
    }

    case 'import': {
      if (!arg) return err('usage: /import <path to backup file>');
      const profile = await call('importIdentity', arg);
      state.profile = profile;
      sys(`identity restored: ${profile.name} ${profile.id}`);
      return;
    }

    case 'clear':
      logEl.replaceChildren();
      return;

    case 'quit':
      window.close();
      return;

    default:
      err(`unknown command /${command} — /help`);
  }
}

async function submit(raw) {
  const text = raw.trim();

  if (state.mode === 'handle') {
    if (!text) return;
    const created = await call('createIdentity', { name: text, sigil: text[0] || '*' });
    line(`> handle: ${text}`, 'me');
    line('');
    await enterReady({ ...created, friends: [] });
    return;
  }

  if (!text) return;

  if (text.startsWith('/')) {
    line(`> ${text}`, 'me');
    try {
      await runCommand(text);
    } catch (e) {
      err(e.message);
    }
    return;
  }

  if (!state.active) {
    err('no conversation open — /chat <name>, or /help');
    return;
  }

  try {
    const message = await call('sendText', { peerId: state.active.id, body: text });
    showMessage('me', message);
    if (message.state === 'queued') {
      line('  (offline — held on this machine until they reappear)', 'sys');
    }
  } catch (e) {
    err(e.message);
  }
}

// --- input ----------------------------------------------------------------

function syncTyped() {
  typedEl.textContent = captureEl.value;
}

captureEl.addEventListener('input', syncTyped);

captureEl.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    const value = captureEl.value;
    captureEl.value = '';
    syncTyped();
    if (value.trim()) {
      state.history.push(value);
      state.historyIndex = state.history.length;
    }
    submit(value).catch((e) => err(e.message));
    return;
  }

  if (event.key === 'ArrowUp') {
    event.preventDefault();
    if (!state.history.length) return;
    state.historyIndex = Math.max(0, state.historyIndex - 1);
    captureEl.value = state.history[state.historyIndex] ?? '';
    syncTyped();
    return;
  }

  if (event.key === 'ArrowDown') {
    event.preventDefault();
    state.historyIndex = Math.min(state.history.length, state.historyIndex + 1);
    captureEl.value = state.history[state.historyIndex] ?? '';
    syncTyped();
  }
});

// Keep focus on the hidden input no matter where the user clicks.
document.addEventListener('mousedown', (event) => {
  if (window.getSelection()?.toString()) return;
  event.preventDefault();
  captureEl.focus();
});
window.addEventListener('focus', () => captureEl.focus());

// --- engine events --------------------------------------------------------

window.mesh.on('mesh:log', (text) => sys(text));

window.mesh.on('mesh:portal', (portal) => describePortal(portal));

window.mesh.on('mesh:message', ({ peerId, name, message }) => {
  if (state.active?.id === peerId) {
    showMessage(name, message);
    return;
  }
  // Not the open conversation: show a preview so you can decide whether to switch.
  const preview = message.body.length > 60 ? `${message.body.slice(0, 60)}...` : message.body;
  line(`* ${name}: ${preview}   (/chat ${name})`, 'hot');
});

window.mesh.on('mesh:delivered', ({ id }) => {
  const el = document.getElementById(`m-${id}`);
  if (!el) return;
  const text = el.textContent.replace(/ \[(~|>)\]$/, '');
  el.textContent = `${text} [ok]`;
});

window.mesh.on('mesh:status', ({ id, name, online }) => {
  if (state.active?.id === id) {
    promptSymbol();
    sys(`${name} is ${online ? 'online' : 'offline'}`);
  }
});

// --- boot -----------------------------------------------------------------

(async function boot() {
  captureEl.focus();
  banner();
  const waking = line('> waking the node...', 'sys');

  try {
    const info = await call('boot');
    waking.remove();

    if (!info.profile) {
      state.mode = 'handle';
      symEl.textContent = 'handle:';
      sys('first run. this machine is about to become a node.');
      sys('pick a handle — it is just a label; your real identity is a key pair.');
      line('');
      return;
    }

    await enterReady(info);
  } catch (e) {
    err(`could not reach the engine: ${e.message}`);
  }
})();
