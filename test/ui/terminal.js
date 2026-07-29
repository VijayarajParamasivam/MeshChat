'use strict';

/**
 * The terminal itself is DOM-bound and cannot be exercised without a browser,
 * so what is checked here is its wiring — read from the source rather than run.
 *
 * That sounds weak, and for most files it would be. It is not here: the one bug
 * this file has actually shipped was `/try` calling an IPC method nobody had
 * written, which no amount of DOM simulation would have caught and a single
 * cross-reference does.
 */

const fs = require('fs');
const path = require('path');

const { suite } = require('../../scripts/harness');

const { check, run } = suite();

const ROOT = path.join(__dirname, '..', '..');
const source = fs.readFileSync(path.join(ROOT, 'src', 'ui', 'terminal.js'), 'utf8');
const mainSource = fs.readFileSync(path.join(ROOT, 'electron', 'main.js'), 'utf8');
const preloadSource = fs.readFileSync(path.join(ROOT, 'electron', 'preload.js'), 'utf8');

run(() => {
  // --- every engine call must have a handler -------------------------------

  const asked = new Set();
  for (const m of source.matchAll(/\bcall\(\s*['"`]([a-zA-Z]+)['"`]/g)) asked.add(m[1]);

  const handlers = mainSource.slice(mainSource.indexOf('const handlers = {'));
  const offered = new Set();
  for (const m of handlers.matchAll(/^\s{2}(?:async\s+)?([a-zA-Z]+)\s*\(/gm)) offered.add(m[1]);

  const orphans = [...asked].filter((method) => !offered.has(method));
  check(
    `every ipc method terminal.js calls exists${orphans.length ? ` (missing: ${orphans.join(', ')})` : ''}`,
    orphans.length === 0
  );
  check('terminal.js calls the engine at all', asked.size > 0);

  // --- every event listened for must be forwarded --------------------------

  const listened = new Set();
  for (const m of source.matchAll(/torchat\.on\(\s*['"`]([\w:-]+)['"`]/g)) listened.add(m[1]);

  const allowed = new Set();
  for (const m of preloadSource.matchAll(/'(torchat:[\w-]+)'/g)) allowed.add(m[1]);

  const unknown = [...listened].filter((event) => !allowed.has(event));
  check(
    `every event terminal.js subscribes to is exposed${unknown.length ? ` (unknown: ${unknown.join(', ')})` : ''}`,
    unknown.length === 0
  );

  // The preload throws on an unknown event name, so an event the main process
  // emits but nobody forwards is silent rather than loud. Worth knowing about.
  const emitted = new Set();
  for (const m of mainSource.matchAll(/send\(\s*['"`](torchat:[\w-]+)['"`]/g)) emitted.add(m[1]);
  const ignored = [...emitted].filter((event) => !listened.has(event));
  check(
    `no engine event goes unheard${ignored.length ? ` (ignored: ${ignored.join(', ')})` : ''}`,
    ignored.length === 0
  );

  // --- the dispatcher ------------------------------------------------------

  check('commands come from the shared table', /window\.createCommands\(/.test(source));
  check('and are dispatched by lookup', /byName\.get\(/.test(source));
  check('the old switch is gone', !/switch \(command/.test(source));
  check('and so is the hand-written help array', !/^const HELP = \[/m.test(source));

  // --- delivery marks ------------------------------------------------------

  check('every message state has a mark', /queued:.*sent:.*delivered:/s.test(source));
  check('delivery receipts update every copy', /rendered\.get\(/.test(source));
  check(
    'a message id is never used as a dom id',
    !/\bel\.id\s*=\s*[`'"]m-/.test(source)
  );

  // --- no node in the renderer ---------------------------------------------
  //
  // contextIsolation means require() is not there to be called, but an
  // accidental one would fail at runtime rather than here.

  check('the renderer never requires node modules', !/\brequire\(/.test(source));
  check('and reaches the engine only through the bridge', !/ipcRenderer/.test(source));
});
