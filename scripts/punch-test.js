'use strict';

/**
 * Does hole punching actually work on your network?
 *
 * Run this on both machines at the same time, each pointing at the other:
 *
 *   node scripts/punch-test.js 2409:40f4:214d:95ae:8927:460a:c8fd:e12f
 *
 * It uses nothing but the punch layer — no identity, no keys, no friend list —
 * so a failure here means the network refused the technique outright rather than
 * something going wrong further up. Worth running before relying on it, because
 * whether a carrier permits reciprocal UDP flows is a property of the carrier
 * and cannot be determined from this end alone.
 *
 * Both ends align to the same wall-clock boundary, so it does not matter who
 * starts first as long as both are running before a window opens.
 */

const punch = require('../src/core/punch');
const portal = require('../src/core/portal');

const PORT = Number(process.argv[3]) || 47777;
const peer = process.argv[2];

function say(text) {
  process.stdout.write(`${text}\n`);
}

async function main() {
  if (!peer) {
    say('usage: node scripts/punch-test.js <peer-address> [port]');
    say('');
    say('run it on both machines at once, each giving the other\'s address.');
    process.exit(1);
  }

  const { global, linkLocal, uniqueLocal } = portal.classifyIPv6();

  say('');
  say('  MeshChat punch test');
  say('  ───────────────────');

  if (global.length) {
    say(`  your address    ${global[0]}`);
    if (global.length > 1) {
      for (const extra of global.slice(1)) say(`                  ${extra}`);
    }
  } else {
    say('  your address    no global IPv6 on this machine');
    if (linkLocal.length || uniqueLocal.length) {
      say('                  (only link-local/unique-local, which cannot be reached)');
    }
    say('  this test needs IPv6 on both ends. run /ipv6 in the app for why.');
    process.exit(1);
  }

  say(`  their address   ${peer}`);
  say(`  port            ${PORT} (both ends must use the same one)`);
  say('');
  say('  give the address above to the other machine, then leave both running.');
  say('');

  const hub = new punch.Hub(PORT);
  hub.on('log', (m) => say(`  ${m}`));

  try {
    await hub.start();
  } catch (err) {
    say(`  could not bind UDP ${PORT}: ${err.message}`);
    say('  is MeshChat already running? close it, or pass a different port.');
    process.exit(1);
  }

  let round = 0;

  const attempt = async () => {
    round += 1;
    const wait = punch.msUntilWindow();
    say(`  round ${round}: next window in ${(wait / 1000).toFixed(1)}s — both ends fire together`);

    try {
      const stream = await hub.punch(peer, PORT);

      say('');
      say('  ✓ PACKETS CROSSED. Hole punching works on this network.');
      say(`    a two-way path is open to ${stream.remoteAddress}`);
      say('');

      // Prove it carries real traffic, not just the punch itself.
      stream.on('data', (chunk) => {
        say(`  ← received: ${chunk.toString('utf8').slice(0, 60)}`);
      });

      let n = 0;
      const chat = setInterval(() => {
        n += 1;
        stream.write(Buffer.from(`hello ${n} from ${global[0]}`, 'utf8'));
        if (n >= 5) {
          clearInterval(chat);
          say('');
          say('  data flowed both ways. MeshChat can use this path.');
          setTimeout(() => {
            hub.stop();
            process.exit(0);
          }, 2000);
        }
      }, 1500);

      stream.on('close', () => {
        clearInterval(chat);
        say('  session closed');
      });

      return;
    } catch (err) {
      say(`  round ${round}: no reply (${err.code || 'failed'})`);

      if (round === 3) {
        say('');
        say('  three windows with nothing crossing. Either the other end is not');
        say('  running yet, or this network drops reciprocal UDP. If you are on a');
        say('  mobile hotspot, that is the likely answer and no client-side change');
        say('  will help — one end needs a connection that accepts inbound.');
        say('');
      }

      setTimeout(attempt, 1000);
    }
  };

  attempt();
}

main().catch((err) => {
  say(`punch test failed: ${err.message}`);
  process.exit(1);
});
