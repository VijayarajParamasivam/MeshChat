'use strict';

/**
 * Every slash command, as data.
 *
 * This used to be a 227-line switch with a separate hand-written help array
 * beside it, and the two drifted: `/try` was listed in the help for a while
 * after the call behind it had stopped existing. One entry per command, with its
 * own help text attached, means the listing cannot disagree with what runs.
 *
 * Loaded as a classic script rather than an ES module on purpose. The renderer
 * is served from file://, where module scripts are blocked as cross-origin, so
 * this exposes a single factory and terminal.js injects what it needs.
 */

/**
 * @param {object} ui  the terminal's own helpers:
 *   call, line, sys, err, state, openChat, promptSymbol, clearLog, describeTor
 * @returns {Array<object>} command definitions in display order
 */
function createCommands(ui) {
  const { call, line, sys, err, state } = ui;

  return [
    {
      name: 'help',
      group: 0,
      help: 'this list',
      run() {
        line('');
        for (const row of helpLines(this.all)) line(row, 'sys');
        line('');
      },
    },
    {
      name: 'who',
      group: 0,
      help: 'your handle, id and data directory',
      async run() {
        const boot = await call('boot');
        sys(`${boot.profile.sigil} ${boot.profile.name}  ${boot.profile.id}`);
        sys(`data ${boot.dataDir}`);
      },
    },
    {
      name: 'me',
      group: 0,
      arg: '<name>',
      help: 'change your display name',
      async run(arg) {
        const profile = await call('setProfile', { name: arg });
        state.profile = profile;
        sys(`you are now ${profile.name}`);
      },
    },
    {
      name: 'sigil',
      group: 0,
      arg: '<char>',
      help: 'change your one-character sigil',
      async run(arg) {
        const profile = await call('setProfile', { sigil: arg });
        state.profile = profile;
        sys(`sigil set to ${profile.sigil}`);
      },
    },

    {
      name: 'card',
      group: 1,
      help: 'print your contact code',
      async run() {
        const code = await call('card');
        line('');
        sys('send this to a friend over any channel you like:');
        line(code, 'hot');
        line('');
        sys('they run /add <code>. only one of you needs to do it.');
      },
    },
    {
      name: 'copy',
      group: 1,
      help: 'copy your contact code to the clipboard',
      async run() {
        await call('copy', await call('card'));
        sys('contact code copied to clipboard');
      },
    },
    {
      name: 'add',
      group: 1,
      arg: '<code>',
      usage: '/add <code or torchat id>',
      help: 'add a friend from their code',
      async run(arg) {
        sys('verifying and dialling...');
        const friend = await call('addFriend', arg);
        sys(`${friend.name} added — /chat ${friend.name}`);
      },
    },
    {
      name: 'paste',
      group: 1,
      help: 'add a friend from a code already on your clipboard',
      async run() {
        const text = await call('paste');
        if (!text) return err('clipboard is empty');
        sys('verifying and dialling...');
        const friend = await call('addFriend', text);
        sys(`${friend.name} added — /chat ${friend.name}`);
      },
    },
    {
      name: 'forget',
      group: 1,
      arg: '<who>',
      help: 'remove a friend',
      async run(arg) {
        const found = await call('resolve', arg);
        if (!found) return err(`no single match for "${arg}"`);
        await call('removeFriend', found.id);
        if (state.active?.id === found.id) state.active = null;
        ui.promptSymbol();
        sys(`forgot ${found.name}`);
      },
    },

    {
      name: 'friends',
      group: 2,
      help: 'who you know and who is online',
      async run() {
        const friends = await call('friends');
        if (!friends.length) return sys('nobody yet. /card to get your code.');
        line('');
        for (const friend of friends) {
          const mark = friend.online ? '[online] ' : '[   off] ';
          line(
            `  ${mark}${friend.sigil} ${friend.name.padEnd(14)} ${friend.id}`,
            friend.online ? 'hot' : 'sys'
          );
        }
        line('');
      },
    },
    {
      name: 'chat',
      group: 2,
      arg: '<who>',
      usage: '/chat <name or torchat id>',
      help: 'open a conversation',
      run(arg) {
        return ui.openChat(arg);
      },
    },
    {
      name: 'leave',
      group: 2,
      help: 'close the conversation',
      run() {
        state.active = null;
        ui.promptSymbol();
        sys('conversation closed');
      },
    },

    {
      name: 'tor',
      group: 3,
      help: 'your onion address and whether it is reachable',
      async run() {
        const t = await call('tor');
        const status = t.running
          ? t.published
            ? 'published and reachable'
            : 'published, still propagating'
          : 'not running';

        line('');
        sys(`onion    ${t.onion || 'not published yet'}`);
        sys(`status   ${status}`);
        sys(`tor      ${t.binary || 'not found'}`);
        sys(`friends  ${t.friends} known, ${t.online} online`);
        line('');

        if (!t.running) {
          line('  tor is not running, so nothing can connect. restart torchat.', 'err');
        } else if (!t.published) {
          line('  the descriptor is still reaching the directory. give it a minute.', 'sys');
        } else {
          line('  friends can reach you at that address from anywhere.', 'hot');
          line('  no ip of yours is published, sent or dialled — only this.', 'sys');
        }
        line('');
      },
    },
    {
      name: 'try',
      group: 3,
      arg: '<who>',
      help: 'force a connection attempt and show why it failed',
      async run(arg) {
        sys(`building a circuit to ${arg} — this takes a few seconds...`);
        const result = await call('probe', arg);

        if (result.alreadyOnline) return sys(`${result.name} is already connected`);

        line('');
        sys(`onion addresses on record for ${result.name}:`);
        if (!result.endpoints.length) {
          line('  (none — their card had no onion address)', 'err');
        }
        for (const e of result.endpoints) line(`  ${e.host}:${e.port}`, 'sys');

        line('');
        if (result.ok) {
          line(`  connected to ${result.name}.`, 'hot');
        } else {
          for (const reason of result.reasons) line(`  ${reason}`, 'err');
          line('', 'sys');
          line('  an onion answers only while their torchat is open. there is no', 'sys');
          line('  firewall or router involved on either side — if this fails, they', 'sys');
          line('  are almost certainly not running it.', 'sys');
        }
        line('');
      },
    },
    {
      name: 'export',
      group: 3,
      help: 'write an identity backup file',
      async run() {
        const file = await call('exportIdentity');
        sys(`identity written to ${file}`);
        line('  anyone holding that file can be you. guard it.', 'err');
      },
    },
    {
      name: 'import',
      group: 3,
      arg: '<path>',
      usage: '/import <path to backup file>',
      help: 'restore an identity backup',
      async run(arg) {
        const profile = await call('importIdentity', arg);
        state.profile = profile;
        sys(`identity restored: ${profile.name} ${profile.id}`);
      },
    },
    {
      name: 'clear',
      group: 3,
      help: 'wipe the screen',
      run() {
        ui.clearLog();
      },
    },
    {
      name: 'quit',
      group: 3,
      help: 'exit',
      run() {
        window.close();
      },
    },
  ];
}

/** Render the command table as the /help listing, grouped and aligned. */
function helpLines(commands) {
  const invocation = (cmd) => `/${cmd.name}${cmd.arg ? ` ${cmd.arg}` : ''}`;
  const width = Math.max(...commands.map((cmd) => invocation(cmd).length)) + 2;

  const rows = [];
  let group = commands[0]?.group;

  for (const cmd of commands) {
    if (cmd.group !== group) {
      rows.push('');
      group = cmd.group;
    }
    rows.push(`  ${invocation(cmd).padEnd(width)}${cmd.help}`);
  }

  rows.push('');
  rows.push('  anything else is sent to whoever you are chatting with.');
  return rows;
}

window.createCommands = createCommands;
