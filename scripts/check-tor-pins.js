'use strict';

/**
 * Check the SHA-256 pins in get-tor.js against the Tor Project's own manifest.
 *
 * The pins exist so that upgrading Tor is a deliberate, reviewable edit — this
 * does not relax that. It catches the opposite mistake: a pin that no longer
 * matches anything upstream, which every user discovers as a failed install and
 * a silently Tor-less app, because get-tor.js refuses to fail the npm install.
 *
 * A network failure here is not a test failure. Being unable to reach the
 * archive says nothing about whether the pins are right.
 */

const https = require('https');
const path = require('path');

const { VERSION, BUNDLES } = require(path.join(__dirname, 'get-tor.js'));

const MANIFEST = `https://archive.torproject.org/tor-package-archive/torbrowser/${VERSION}/sha256sums-unsigned-build.txt`;

function fetch(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    if (redirects < 0) return reject(new Error('too many redirects'));
    https
      .get(url, { headers: { 'User-Agent': 'TorChat-pin-check' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(fetch(new URL(res.headers.location, url).toString(), redirects - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`server said ${res.statusCode}`));
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => resolve(body));
      })
      .on('error', reject);
  });
}

(async () => {
  let manifest;
  try {
    manifest = await fetch(MANIFEST);
  } catch (err) {
    console.log(`skipped: could not reach the manifest (${err.message})`);
    return;
  }

  const upstream = new Map();
  for (const row of manifest.split('\n')) {
    const match = row.trim().match(/^([0-9a-f]{64})\s+(\S+)$/);
    if (match) upstream.set(match[2], match[1]);
  }

  let failures = 0;
  for (const [platform, bundle] of Object.entries(BUNDLES)) {
    const actual = upstream.get(bundle.file);
    if (!actual) {
      console.log(`FAIL  ${platform}: ${bundle.file} is not in the ${VERSION} manifest`);
      failures++;
    } else if (actual !== bundle.sha256) {
      console.log(`FAIL  ${platform}: pinned ${bundle.sha256.slice(0, 16)}…, manifest says ${actual.slice(0, 16)}…`);
      failures++;
    } else {
      console.log(`PASS  ${platform}`);
    }
  }

  console.log(failures ? `\n${failures} pin(s) wrong` : `\nall ${VERSION} pins match`);
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
