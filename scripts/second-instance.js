'use strict';

/**
 * Launch a second, fully independent TorChat on this machine so you can talk
 * to yourself. It gets its own data directory — its own keys, its own friend
 * list, and its own onion address, since the onion key lives in there too.
 *
 * There is no port to coordinate. The local listener takes whatever the OS
 * hands it and only Tor ever connects to it, so two instances never collide.
 */

const { spawn } = require('child_process');
const electron = require('electron');

spawn(electron, ['.'], {
  stdio: 'inherit',
  env: { ...process.env, TORCHAT_PROFILE: process.env.TORCHAT_PROFILE || 'b' },
}).on('exit', (code) => process.exit(code ?? 0));
