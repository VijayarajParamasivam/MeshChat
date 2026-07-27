'use strict';

/**
 * Launch a second, fully independent MeshChat on this machine so you can talk
 * to yourself. It gets its own data directory (its own keys, its own friend
 * list) and the TCP port auto-increments because the first one is taken.
 */

const { spawn } = require('child_process');
const electron = require('electron');

spawn(electron, ['.'], {
  stdio: 'inherit',
  env: { ...process.env, MESH_PROFILE: process.env.MESH_PROFILE || 'b' },
}).on('exit', (code) => process.exit(code ?? 0));
