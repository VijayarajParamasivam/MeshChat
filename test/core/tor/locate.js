'use strict';

/**
 * Finding a tor binary.
 *
 * The path list is order-sensitive and one of those orderings is load-bearing:
 * in a packaged app `process.resourcesPath` must come before the dev-time
 * vendor path, because __dirname points inside the .asar archive where nothing
 * is executable.
 */

const path = require('path');

const { find, installHint, candidatePaths } = require('../../../src/core/tor/locate');
const { suite } = require('../../../scripts/harness');

const { check, run } = suite();

run(() => {
  const paths = candidatePaths();

  check('there are candidates to try', paths.length > 0);
  check('every candidate is a string', paths.every((p) => typeof p === 'string'));
  check(
    'the vendored binary is among them',
    paths.some((p) => p.includes(`vendor${path.sep}tor`))
  );

  // The vendor path is built by walking up from this module. Getting that depth
  // wrong resolves to a directory that does not exist, and the app silently
  // falls through to whatever tor happens to be on PATH.
  const vendor = paths.find((p) => p.includes(`vendor${path.sep}tor`));
  check('the vendor path escapes src/core/tor', !vendor.includes(`src${path.sep}core`));
  check(
    'the vendor path sits at the repo root',
    path.resolve(vendor).startsWith(path.resolve(__dirname, '..', '..', '..'))
  );

  const exe = process.platform === 'win32' ? 'tor.exe' : 'tor';
  check('candidates end in the platform binary', paths.every((p) => p.endsWith(exe) || p === 'tor'));

  // An explicit override must win outright.
  const before = process.env.TORCHAT_TOR;
  process.env.TORCHAT_TOR = path.join('X:', 'custom', exe);
  check('TORCHAT_TOR is tried first', candidatePaths()[0] === process.env.TORCHAT_TOR);
  if (before === undefined) delete process.env.TORCHAT_TOR;
  else process.env.TORCHAT_TOR = before;

  // find() returns a path or null; it must never throw on a machine with no tor.
  const found = find();
  check('find returns a path or null', found === null || typeof found === 'string');

  // --- guidance ------------------------------------------------------------

  const hint = installHint();
  check('there is a usable hint when tor is missing', hint.length > 0);
  check('the hint is printable lines', hint.every((row) => typeof row === 'string'));
  check('the hint names the project', hint.join(' ').includes('torproject.org') || hint.join(' ').includes('apt install tor'));
  check('the hint mentions the override', hint.join(' ').includes('TORCHAT_TOR'));
});
