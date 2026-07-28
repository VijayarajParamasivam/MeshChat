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
  line(' every connection is an onion service.', 'hot');
  line(' no ip of yours is ever published, sent, or dialled.', 'sys');
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

  if (boot.tor) describeTor(boot.tor);

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

function describeTor(t) {
  if (!t) return;

  if (!t.running) {
    sys('tor      not running — nothing can connect');
    return;
  }

  sys(`onion    ${t.onion}`);
  line(
    t.published
      ? '  reachable from anywhere. no firewall, router or ip involved.'
      : '  publishing — friends may need a minute before they can reach you.',
    t.published ? 'hot' : 'sys'
  );
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
  '  /add <code>        add a friend from their code',
  '  /paste             add a friend from a code already on your clipboard',
  '  /forget <who>      remove a friend',
  '',
  '  /friends           who you know and who is online',
  '  /chat <who>        open a conversation',
  '  /leave             close the conversation',
  '',
  '  /tor               your onion address and whether it is reachable',
  '  /try <who>         force a connection attempt and show why it failed',
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

    case 'tor': {
      const t = await call(`tor`);
      line('');
      sys(`onion    ${t.onion || 'not published yet'}`);
      sys(`status   ${t.running ? (t.published ? 'published and reachable' : 'published, still propagating') : 'not running'}`);
      sys(`tor      ${t.binary || 'not found'}`);
      sys(`friends  ${t.friends} known, ${t.online} online`);
      line('');
      if (!t.running) {
        line('  tor is not running, so nothing can connect. restart meshchat.', 'err');
      } else if (!t.published) {
        line('  the descriptor is still reaching the directory. give it a minute.', 'sys');
      } else {
        line('  friends can reach you at that address from anywhere.', 'hot');
        line('  no ip of yours is published, sent or dialled — only this.', 'sys');
      }
      line('');
      return;
    }

    case 'try': {
      if (!arg) return err('usage: /try <who>');
      sys(`building a circuit to ${arg} — this takes a few seconds...`);
      const result = await call('probe', arg);

      if (result.alreadyOnline) return sys(`${result.name} is already connected`);

      line('');
      sys(`onion addresses on record for ${result.name}:`);
      if (!result.endpoints.length) line('  (none — their card had no onion address)', 'err');
      for (const e of result.endpoints) line(`  ${e.host}:${e.port}`, 'sys');

      line('');
      if (result.ok) {
        line(`  connected to ${result.name}.`, 'hot');
      } else {
        for (const reason of result.reasons) line(`  ${reason}`, 'err');
        line('', 'sys');
        line('  an onion answers only while their meshchat is open. there is no', 'sys');
        line('  firewall or router involved on either side — if this fails, they', 'sys');
        line('  are almost certainly not running it.', 'sys');
      }
      line('');
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

window.mesh.on('mesh:ready', (status) => describeTor(status));

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
