'use strict';

/**
 * The renderer, checked without a browser.
 *
 * `ui/commands.js` is a classic script that hands its table to `window`, so it
 * loads here in a vm sandbox with a fake window and no DOM at all. That is
 * enough to exercise every command's plumbing.
 *
 * The test that earns its place is the last one: every engine method a command
 * asks for must actually exist in electron/main.js. `/try` called a `probe`
 * handler that had never been written, and nothing anywhere noticed — the whole
 * command was dead on arrival and the suite stayed green.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let failures = 0;
function check(name, condition) {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}`);
  if (!condition) failures++;
}

const ROOT = path.join(__dirname, '..', '..');
const commandsSource = fs.readFileSync(path.join(ROOT, 'src', 'ui', 'commands.js'), 'utf8');
const mainSource = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const terminalSource = fs.readFileSync(path.join(ROOT, 'src', 'ui', 'terminal.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(ROOT, 'src', 'ui', 'index.html'), 'utf8');

/** Load ui/commands.js the way the page does, and return its factory. */
function loadFactory() {
  const sandbox = { window: {}, console };
  vm.createContext(sandbox);
  vm.runInContext(commandsSource, sandbox, { filename: 'ui/commands.js' });
  return sandbox.window.createCommands;
}

/** A recording stand-in for everything terminal.js injects. */
function fakeUi() {
  const calls = [];
  const printed = [];
  const ui = {
    calls,
    printed,
    state: { profile: null, active: null },
    call: async (method, payload) => {
      calls.push({ method, payload });
      return fakeReplies[method] ?? null;
    },
    line: (text) => printed.push(String(text)),
    sys: (text) => printed.push(`> ${text}`),
    err: (text) => printed.push(`! ${text}`),
    openChat: async (q) => printed.push(`openChat:${q}`),
    promptSymbol: () => {},
    clearLog: () => printed.push('CLEARED'),
  };
  return ui;
}

const fakeReplies = {
  boot: { profile: { id: 'TOR-A', name: 'a', sigil: 'a' }, dataDir: '/tmp/x' },
  card: 'TORCHAT1.xxx',
  friends: [{ id: 'TOR-B', name: 'bob', sigil: 'b', online: true }],
  tor: { onion: 'x.onion', running: true, published: true, binary: '/tor', friends: 1, online: 1 },
  probe: { name: 'bob', id: 'TOR-B', ok: true, alreadyOnline: false, endpoints: [], reasons: [] },
  resolve: { id: 'TOR-B', name: 'bob' },
  setProfile: { id: 'TOR-A', name: 'a', sigil: 'a' },
  addFriend: { id: 'TOR-B', name: 'bob' },
  exportIdentity: '/tmp/backup.json',
  importIdentity: { id: 'TOR-A', name: 'a' },
  paste: 'TORCHAT1.yyy',
};

(async () => {
  const createCommands = loadFactory();
  check('commands.js exposes its factory', typeof createCommands === 'function');

  const commands = createCommands(fakeUi());
  for (const command of commands) command.all = commands;

  const names = commands.map((c) => c.name);
  check('every command has a name and a runner', commands.every((c) => c.name && c.run));
  check('every command has help text', commands.every((c) => c.help));
  check('names are unique', new Set(names).size === names.length);

  // The page must load the table before the script that reads it.
  const commandsAt = indexHtml.indexOf('commands.js');
  const terminalAt = indexHtml.indexOf('terminal.js');
  check('index.html loads commands.js', commandsAt !== -1);
  check('and loads it before terminal.js', commandsAt !== -1 && commandsAt < terminalAt);

  // --- /help is generated from the table, so it cannot drift ---------------

  {
    const ui = fakeUi();
    const table = createCommands(ui);
    for (const command of table) command.all = table;
    await table.find((c) => c.name === 'help').run('');

    const text = ui.printed.join('\n');
    const missing = table.filter((c) => !text.includes(`/${c.name}`));
    check('/help lists every command', missing.length === 0);
    check('/help mentions plain messages', /anything else is sent/.test(text));
  }

  // --- commands that need an argument declare it --------------------------

  {
    const needArgs = ['me', 'sigil', 'add', 'forget', 'chat', 'try', 'import'];
    const declared = needArgs.every((name) => commands.find((c) => c.name === name)?.arg);
    check('commands taking an argument declare one', declared);

    const takesNone = ['help', 'who', 'card', 'copy', 'paste', 'friends', 'leave', 'tor', 'clear'];
    const clean = takesNone.every((name) => !commands.find((c) => c.name === name)?.arg);
    check('commands taking none declare none', clean);
  }

  // --- each command actually runs -----------------------------------------

  {
    const skip = new Set(['quit']); // would close the window
    let ran = 0;
    for (const command of commands) {
      if (skip.has(command.name)) continue;
      const ui = fakeUi();
      const table = createCommands(ui);
      for (const c of table) c.all = table;
      const target = table.find((c) => c.name === command.name);
      await target.run('bob');
      ran += 1;
    }
    check('every command runs without throwing', ran === commands.length - skip.size);
  }

  // --- the bug that started all this --------------------------------------

  {
    // Every engine method the UI asks for, from both renderer files.
    const asked = new Set();
    for (const source of [commandsSource, terminalSource]) {
      for (const m of source.matchAll(/\bcall\(\s*['"`]([a-zA-Z]+)['"`]/g)) asked.add(m[1]);
    }

    // Every method electron/main.js is willing to answer.
    const handlersBlock = mainSource.slice(mainSource.indexOf('const handlers = {'));
    const offered = new Set();
    for (const m of handlersBlock.matchAll(/^\s{2}(?:async\s+)?([a-zA-Z]+)\s*\(/gm)) {
      offered.add(m[1]);
    }

    const orphans = [...asked].filter((method) => !offered.has(method));
    check(
      `every ipc method the ui calls exists in main.js${orphans.length ? ` (missing: ${orphans.join(', ')})` : ''}`,
      orphans.length === 0
    );
    check('the ui calls something at all', asked.size > 5);
  }

  console.log(failures ? `\n${failures} failing` : '\nall good');
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
