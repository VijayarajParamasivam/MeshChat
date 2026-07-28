'use strict';

/**
 * Fetch the Tor binary MeshChat needs, so `npm install` leaves a working app.
 *
 * Runs from `postinstall`. Tor is not an npm package and there is no meaningful
 * way to vendor a 15 MB platform-specific binary in git, so it is downloaded
 * from the Tor Project's own archive and checked against a pinned SHA-256.
 *
 * The checksums below were taken from the signed release manifest at
 * https://archive.torproject.org/tor-package-archive/torbrowser/15.0.19/sha256sums-unsigned-build.txt
 * and are pinned rather than fetched. Downloading the checksum alongside the
 * file it is meant to vouch for proves only that they came from the same place,
 * which is exactly what an attacker able to serve one can serve. Pinning means
 * upgrading Tor is a deliberate edit to this file, reviewable in a diff.
 *
 * Nothing here runs the binary. It is unpacked and left alone until the app
 * starts it, and if the hash does not match it is deleted rather than kept.
 */

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const VERSION = '15.0.19';
const BASE = `https://archive.torproject.org/tor-package-archive/torbrowser/${VERSION}`;

/** SHA-256 of each expert bundle, from the release manifest for this version. */
const BUNDLES = {
  'win32-x64': {
    file: `tor-expert-bundle-windows-x86_64-${VERSION}.tar.gz`,
    sha256: '6ac067402c7b4a3dc37887ed3754b3914b67fdc220c966190683e9ccf91abf0f',
  },
  'win32-ia32': {
    file: `tor-expert-bundle-windows-i686-${VERSION}.tar.gz`,
    sha256: 'aaf3786d119a2d61607640e392e0a2e7ede4057f050509c81189b3e9e11d46bb',
  },
  'linux-x64': {
    file: `tor-expert-bundle-linux-x86_64-${VERSION}.tar.gz`,
    sha256: '5a8f19f5f119b5fa2a8fd799a3a532e3236ad36164241800d6302e32f0e1c2a9',
  },
  'linux-ia32': {
    file: `tor-expert-bundle-linux-i686-${VERSION}.tar.gz`,
    sha256: '8e6310a528c34b5e671359533ccdc7d8142e3d2a5a46c007b3b23c703198f2af',
  },
  'darwin-x64': {
    file: `tor-expert-bundle-macos-x86_64-${VERSION}.tar.gz`,
    sha256: '95243f76bcf05d6179d017c3f3e4ece7b53cc58dff1ba617b03a2fe2c8298b5b',
  },
  'darwin-arm64': {
    file: `tor-expert-bundle-macos-aarch64-${VERSION}.tar.gz`,
    sha256: 'c99cf6f69740a443c7fffaf598ceb0952b3914041507c8afe11bed84a3333eb1',
  },
};

const VENDOR = path.join(__dirname, '..', 'vendor', 'tor');

function say(text) {
  process.stdout.write(`${text}\n`);
}

function binaryPath() {
  return path.join(VENDOR, 'tor', process.platform === 'win32' ? 'tor.exe' : 'tor');
}

function pick() {
  // macOS on Apple silicon runs the x86_64 build fine under Rosetta, but the
  // native one is there, so prefer an exact match and fall back by arch.
  const exact = `${process.platform}-${process.arch}`;
  if (BUNDLES[exact]) return BUNDLES[exact];
  if (process.platform === 'darwin' && process.arch === 'arm64') return BUNDLES['darwin-arm64'];
  return null;
}

function download(url, destination, redirects = 5) {
  return new Promise((resolve, reject) => {
    if (redirects < 0) return reject(new Error('too many redirects'));

    https
      .get(url, { headers: { 'User-Agent': 'MeshChat-installer' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(download(new URL(res.headers.location, url).toString(), destination, redirects - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`server said ${res.statusCode}`));
        }

        const total = Number(res.headers['content-length']) || 0;
        let seen = 0;
        let lastShown = 0;

        const file = fs.createWriteStream(destination);
        res.on('data', (chunk) => {
          seen += chunk.length;
          const percent = total ? Math.floor((seen / total) * 100) : 0;
          if (total && percent >= lastShown + 20) {
            lastShown = percent;
            say(`  ${percent}%`);
          }
        });

        res.pipe(file);
        file.on('finish', () => file.close(resolve));
        file.on('error', reject);
      })
      .on('error', reject);
  });
}

function sha256(file) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(file));
  return hash.digest('hex');
}

/**
 * Both Windows 10+ and every Unix ship a tar capable of gzip, so unpacking
 * shells out rather than pulling in a tar library for one call at install time.
 *
 * The archive is named relative to `cwd` rather than by absolute path on
 * purpose: GNU tar reads the colon in `C:\Users\...` as a remote host
 * separator and tries to fetch the file from a machine called "C". Passing a
 * bare filename sidesteps that, and works identically under the bsdtar that
 * ships with Windows.
 */
function extract(archive, into) {
  fs.mkdirSync(into, { recursive: true });
  execFileSync('tar', ['-xzf', path.basename(archive)], { cwd: into, stdio: 'ignore' });
}

async function main() {
  if (process.env.MESHCHAT_SKIP_TOR) {
    say('meshchat: MESHCHAT_SKIP_TOR set, skipping the Tor download.');
    return;
  }

  if (fs.existsSync(binaryPath())) {
    say(`meshchat: tor ${VERSION} already present.`);
    return;
  }

  const bundle = pick();
  if (!bundle) {
    say(`meshchat: no Tor build for ${process.platform}/${process.arch}.`);
    say('  install tor yourself and set MESHCHAT_TOR to its path.');
    return;
  }

  fs.mkdirSync(VENDOR, { recursive: true });
  const archive = path.join(VENDOR, bundle.file);

  say(`meshchat: downloading tor ${VERSION} (about 15 MB)...`);

  try {
    await download(`${BASE}/${bundle.file}`, archive);

    const got = sha256(archive);
    if (got !== bundle.sha256) {
      // Refuse to keep a binary we cannot vouch for. A truncated download and a
      // tampered one look identical from here, and neither should be run.
      fs.unlinkSync(archive);
      throw new Error(
        `checksum mismatch — expected ${bundle.sha256.slice(0, 16)}…, got ${got.slice(0, 16)}…`
      );
    }

    extract(archive, VENDOR);
    fs.unlinkSync(archive);

    if (process.platform !== 'win32') fs.chmodSync(binaryPath(), 0o755);

    if (!fs.existsSync(binaryPath())) {
      throw new Error('archive unpacked but no tor binary was found inside it');
    }

    say(`meshchat: tor ready at vendor/tor. run "npm start" to begin.`);
  } catch (err) {
    // A failed download must not fail the install. The app still runs, and
    // /tor explains what is missing and how to supply it by hand.
    //
    // A verified archive is kept so a retry does not re-download 15 MB; only an
    // unverified one is destroyed, and that happens above where it is detected.
    say(`meshchat: could not fetch tor (${err.message}).`);
    say('  MeshChat will still start, but /tor and /private need it.');
    say('  Retry with "npm run get-tor", or install Tor Browser and let');
    say('  MeshChat find its bundled binary automatically.');
  }
}

main().catch((err) => {
  say(`meshchat: tor setup failed (${err.message}) — continuing anyway.`);
});
