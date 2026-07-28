'use strict';

/**
 * Electron main process: owns the P2P engine and exposes it to the terminal UI
 * over IPC. The renderer has no Node access at all — it only sees the narrow
 * surface defined in preload.js.
 *
 * Set MESH_PROFILE to run a second, completely independent identity on the same
 * machine (separate data directory; the TCP port auto-increments). That's how
 * you talk to yourself for testing.
 */

const path = require('path');
const fs = require('fs');
const { app, BrowserWindow, ipcMain, clipboard } = require('electron');

const firewall = require('../src/core/firewall');
const identity = require('../src/core/identity');
const ipv6doctor = require('../src/core/ipv6doctor');
const store = require('../src/core/store');
const { Mesh } = require('../src/core/roster');

const profileName = process.env.MESH_PROFILE || '';
if (profileName) {
  app.setPath('userData', `${app.getPath('userData')}-${profileName}`);
}

let win = null;
let mesh = null;
let starting = null;

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

/** Boot the engine once an identity exists. Safe to call repeatedly. */
function startEngine() {
  if (mesh) return Promise.resolve(mesh);
  if (starting) return starting;

  const engine = new Mesh();
  engine.on('log', (text) => send('mesh:log', text));
  engine.on('status', (payload) => send('mesh:status', payload));
  engine.on('message', (payload) => send('mesh:message', payload));
  engine.on('delivered', (payload) => send('mesh:delivered', payload));
  engine.on('portal', (payload) => send('mesh:portal', payload));
  engine.on('friends-changed', () => send('mesh:friends-changed'));
  engine.on('history-changed', (payload) => send('mesh:history-changed', payload));

  starting = engine
    .start()
    .then(() => {
      mesh = engine;
      starting = null;
      return mesh;
    })
    .catch((err) => {
      starting = null;
      send('mesh:log', `engine failed to start: ${err.message}`);
      throw err;
    });

  return starting;
}

function requireEngine() {
  if (!mesh) throw new Error('no identity yet — set a handle first');
  return mesh;
}

function createWindow() {
  win = new BrowserWindow({
    width: 940,
    height: 660,
    backgroundColor: '#000000',
    title: profileName ? `MeshChat [${profileName}]` : 'MeshChat',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.loadFile(path.join(__dirname, '..', 'ui', 'index.html'));
}

app.whenReady().then(() => {
  store.init(app.getPath('userData'));

  if (identity.load()) startEngine().catch(() => {});

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => app.quit());

let cleanedUp = false;
app.on('before-quit', async (event) => {
  if (cleanedUp) return;
  event.preventDefault();
  cleanedUp = true;
  try {
    if (mesh) await mesh.stop();
    else store.flush();
  } catch {
    /* shutting down anyway */
  }
  app.quit();
});

// --- IPC ------------------------------------------------------------------

const handlers = {
  async boot() {
    // Router negotiation takes a few seconds. Wait it out so the first screen
    // shows real network status instead of racing the engine.
    if (starting) {
      try {
        await starting;
      } catch {
        /* the log already carries the reason */
      }
    }

    const profile = identity.profile();
    return {
      profile,
      running: Boolean(mesh),
      portal: mesh ? mesh.portalStatus() : null,
      firewall: await firewall.status(),
      port: mesh ? mesh.port : null,
      friends: mesh ? mesh.list() : [],
      dataDir: store.root,
      instance: profileName || null,
    };
  },

  async createIdentity({ name, sigil }) {
    if (identity.get()) throw new Error('an identity already exists here');
    identity.create(name, sigil);
    await startEngine();
    return { profile: identity.profile(), portal: mesh.portalStatus() };
  },

  card() {
    return requireEngine().myCard();
  },

  copy(text) {
    clipboard.writeText(String(text));
    return true;
  },

  paste() {
    return clipboard.readText();
  },

  async addFriend(code) {
    const friend = await requireEngine().addFriend(code);
    return { id: friend.id, name: friend.name };
  },

  removeFriend(id) {
    return requireEngine().removeFriend(id);
  },

  friends() {
    return mesh ? mesh.list() : [];
  },

  nearby() {
    return requireEngine().nearbyList();
  },

  resolve(query) {
    const friend = requireEngine().resolve(query);
    return friend ? { id: friend.id, name: friend.name } : null;
  },

  history({ peerId, limit }) {
    return requireEngine().history(peerId, limit);
  },

  sendText({ peerId, body }) {
    return requireEngine().sendText(peerId, body);
  },

  setProfile(patch) {
    return requireEngine().setProfile(patch);
  },

  async net() {
    const engine = requireEngine();
    return {
      ...engine.portalStatus(),
      port: engine.port,
      firewall: await firewall.status(),
    };
  },

  async openFirewall() {
    return firewall.install(requireEngine().port);
  },

  async probe(query) {
    const engine = requireEngine();
    const friend = engine.resolve(query);
    if (!friend) throw new Error(`no single match for "${query}"`);
    return { name: friend.name, ...(await engine.probe(friend.id)) };
  },

  async punch(query) {
    const engine = requireEngine();
    const friend = engine.resolve(query);
    if (!friend) throw new Error(`no single match for "${query}"`);
    return {
      name: friend.name,
      windowMs: engine.nextPunchWindowMs(),
      ...(await engine.punchProbe(friend.id)),
    };
  },

  async tor() {
    return requireEngine().torStatus();
  },

  async setTor(patch) {
    const engine = requireEngine();
    engine.setTor(patch || {});
    return engine.torStatus();
  },

  async ipv6() {
    return ipv6doctor.diagnose();
  },

  exportIdentity() {
    const file = path.join(store.root, 'meshchat-identity-backup.json');
    fs.writeFileSync(file, identity.exportBackup(), 'utf8');
    return file;
  },

  async importIdentity(file) {
    identity.importBackup(fs.readFileSync(file, 'utf8'));
    if (mesh) await mesh.stop();
    mesh = null;
    await startEngine();
    return identity.profile();
  },
};

ipcMain.handle('mesh:call', async (_event, method, payload) => {
  const handler = handlers[method];
  if (!handler) throw new Error(`unknown call ${method}`);
  try {
    return { ok: true, value: await handler(payload) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});
