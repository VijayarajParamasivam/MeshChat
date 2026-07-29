'use strict';

/**
 * Finding a tor binary to drive, and explaining how to get one when there isn't.
 *
 * TorChat never asks the user to configure this. `npm install` vendors a binary,
 * a packaged build carries one, and most people who care already have Tor
 * Browser — whose bundled tor works perfectly well driven by hand, so we use it
 * and never launch the browser itself.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

/** Where the vendored binary lands, relative to this file. */
const VENDOR_TOR = path.join(__dirname, '..', '..', '..', 'vendor', 'tor', 'tor');

/** Somewhere to find a tor binary, in order of preference. */
function candidatePaths() {
  const exe = process.platform === 'win32' ? 'tor.exe' : 'tor';
  const home = os.homedir();
  const list = [];

  if (process.env.TORCHAT_TOR) list.push(process.env.TORCHAT_TOR);

  // In a packaged Electron app, extraResources places files under
  // process.resourcesPath. This must come before the dev-time path below
  // because __dirname points inside the .asar archive.
  if (typeof process.resourcesPath === 'string') {
    list.push(path.join(process.resourcesPath, 'tor', 'tor', exe));
  }

  // What `npm install` fetched. First choice in dev, so a clean clone works
  // with no setup and without depending on whatever Tor the machine happens
  // to have.
  list.push(path.join(VENDOR_TOR, exe));

  if (process.platform === 'win32') {
    list.push(...torBrowserPaths(home, exe));
  } else {
    list.push('/usr/bin/tor', '/usr/local/bin/tor', '/opt/homebrew/bin/tor');
    list.push(path.join(home, '.local', 'bin', 'tor'));
  }

  return list;
}

/** Every place a Windows Tor Browser install is likely to have put its tor.exe. */
function torBrowserPaths(home, exe) {
  const roots = [
    path.join(home, 'Desktop', 'Tor Browser'),
    path.join(process.env.LOCALAPPDATA || '', 'Tor Browser'),
    path.join(process.env.PROGRAMFILES || '', 'Tor Browser'),
    path.join(home, 'Downloads', 'tor'),
  ];

  const found = [];
  for (const root of roots) {
    if (!root) continue;
    found.push(path.join(root, 'Browser', 'TorBrowser', 'Tor', exe));
    found.push(path.join(root, exe));
  }
  return found;
}

function isRunnableFile(candidate) {
  try {
    return Boolean(candidate) && fs.existsSync(candidate) && fs.statSync(candidate).isFile();
  } catch {
    return false; // unreadable path, keep looking
  }
}

/** @returns {string|null} path to a usable tor binary */
function find() {
  const found = candidatePaths().find(isRunnableFile);
  if (found) return found;

  // Last resort: whatever is on PATH. spawn resolves it, so existence is only
  // proven when we actually try to run it.
  return process.platform === 'win32' ? null : 'tor';
}

function installHint() {
  if (process.platform === 'win32') {
    return [
      'Tor is not installed. Two ways to fix that:',
      '',
      '  1. Install Tor Browser from https://www.torproject.org/download/',
      '     TorChat finds its bundled tor.exe automatically and never opens',
      '     the browser itself.',
      '',
      '  2. Or download the "Tor Expert Bundle" from the same page, unzip it,',
      '     and point TorChat at it:  set TORCHAT_TOR=C:\\path\\to\\tor.exe',
    ];
  }
  return [
    'Tor is not installed. Install it with your package manager:',
    '  apt install tor      (Debian/Ubuntu)',
    '  brew install tor     (macOS)',
    'Then restart TorChat.',
  ];
}

module.exports = { find, installHint, candidatePaths };
