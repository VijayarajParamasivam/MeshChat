'use strict';

/**
 * Find every suite under test/ and run it.
 *
 * The layout of test/ mirrors src/ exactly — test/core/tor/socks.js covers
 * src/core/tor/socks.js — so discovery is a directory walk rather than a list
 * anyone has to remember to update. A new source file with no suite beside it
 * shows up as a gap here rather than as silence.
 *
 * Each suite is a separate process. They bind ports, spawn nothing, and call
 * process.exit, so isolating them keeps one crash from taking the run with it.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const TEST_DIR = path.join(__dirname, '..', 'test');
const SRC_DIR = path.join(__dirname, '..', 'src');

/**
 * Every .js file under test/ is a suite — there are no exceptions to skip.
 *
 * The shared assertion helper lives in scripts/harness.js rather than in here
 * precisely so that stays true: test/ contains mirrors and nothing else, which
 * is what lets the gap check below be a plain set comparison.
 */
function walk(dir) {
  const found = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...walk(full));
    else if (entry.name.endsWith('.js')) found.push(full);
  }
  return found.sort();
}

const asKey = (from, file) => path.relative(from, file).split(path.sep).join('/');

/**
 * Where the two trees disagree.
 *
 * test/ mirrors src/ one file for one file, so this is a straight set
 * difference in both directions: a source nobody tests, and a suite testing
 * something that no longer exists.
 */
function mirrorGaps(suites) {
  const tested = new Set(suites.map((file) => asKey(TEST_DIR, file)));
  const sources = new Set(walk(SRC_DIR).map((file) => asKey(SRC_DIR, file)));

  return {
    untested: [...sources].filter((rel) => !tested.has(rel)),
    orphaned: [...tested].filter((rel) => !sources.has(rel)),
  };
}

const suites = walk(TEST_DIR);
if (!suites.length) {
  console.error('no suites found under test/');
  process.exit(1);
}

let failed = 0;
let passed = 0;

for (const suite of suites) {
  const label = path.relative(TEST_DIR, suite).split(path.sep).join('/');
  console.log(`\n── ${label} ${'─'.repeat(Math.max(0, 60 - label.length))}`);

  const result = spawnSync(process.execPath, [suite], { stdio: 'inherit' });
  if (result.status === 0) passed += 1;
  else failed += 1;
}

console.log(`\n${'='.repeat(64)}`);
console.log(`${passed} suite(s) passed, ${failed} failed`);

// Not a failure, but worth saying out loud — a source file nobody tests is how
// a whole command shipped dead once already, and a suite for a file that no
// longer exists is testing a ghost.
const { untested, orphaned } = mirrorGaps(suites);
if (untested.length) console.log(`\nno suite mirrors: ${untested.join(', ')}`);
if (orphaned.length) console.log(`\nno source behind: ${orphaned.join(', ')}`);

process.exit(failed ? 1 : 0);
