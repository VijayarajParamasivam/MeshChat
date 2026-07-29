'use strict';

/**
 * Electron main process: owns the P2P engine and exposes it to the terminal UI
 * over IPC. The renderer has no Node access at all — it only sees the narrow
 * surface defined in preload.js.
 *
 * Set TORCHAT_PROFILE to run a second, completely independent identity on the same
 * machine (separate data directory; the TCP port auto-increments). That's how
 * you talk to yourself for testing.
 */

const path = require('path');
const fs = require('fs');
const { app, BrowserWindow, ipcMain, clipboard } = require('electron');

const identity = require('../src/core/identity');
const store = require('../src/core/store');
const { TorChat } = require('../src/core/roster');

const profileName = process.env.TORCHAT_PROFILE || '';
if (profileName) {
  app.setPath('userData', `${app.getPath('userData')}-${profileName}`);
}

let win = null;
let active = null;
let starting = null;

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

/** Boot the engine once an identity exists. Safe to call repeatedly. */
function startEngine() {
  if (active) return Promise.resolve(active);
  if (starting) return starting;

  const engine = new TorChat();
  engine.on('log', (text) => send('torchat:log', text));
  engine.on('status', (payload) => send('torchat:status', payload));
  engine.on('message', (payload) => send('torchat:message', payload));
  engine.on('delivered', (payload) => send('torchat:delivered', payload));
  engine.on('ready', (payload) => send('torchat:ready', payload));
  engine.on('friends-changed', () => send('torchat:friends-changed'));
  engine.on('history-changed', (payload) => send('torchat:history-changed', payload));

  starting = engine
    .start()
    .then(() => {
      active = engine;
      starting = null;
      return active;
    })
    .catch(async (err) => {
      starting = null;
      // Whatever it got as far as bringing up — the loopback listener, tor
      // itself — has to come down with it, or a retry meets its own leftovers.
      try {
        await engine.stop();
      } catch {
        /* it failed to start; it may have nothing to stop */
      }
      send('torchat:log', `engine failed to start: ${err.message}`);
      throw err;
    });

  return starting;
}

function requireEngine() {
  if (!active) throw new Error('no identity yet — set a handle first');
  return active;
}

function createWindow() {
  win = new BrowserWindow({
    width: 940,
    height: 660,
    backgroundColor: '#000000',
    title: profileName ? `TorChat [${profileName}]` : 'TorChat',
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
    if (active) await active.stop();
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
      running: Boolean(active),
      tor: active ? active.status() : null,
      port: active ? active.port : null,
      friends: active ? active.list() : [],
      dataDir: store.root,
      instance: profileName || null,
    };
  },

  async createIdentity({ name, sigil }) {
    if (identity.get()) throw new Error('an identity already exists here');
    identity.create(name, sigil);

    // The identity is on disk from here whether or not Tor comes up, so a
    // failure to start must not be reported as a failure to create. Throwing
    // left the UI asking for a handle again and the second attempt hitting
    // "an identity already exists here" — an app bricked until restart by
    // nothing worse than Tor being slow.
    try {
      await startEngine();
    } catch (err) {
      return { profile: identity.profile(), tor: null, error: err.message };
    }

    return { profile: identity.profile(), tor: active.status() };
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
    return active ? active.list() : [];
  },

  resolve(query) {
    const friend = requireEngine().resolve(query);
    return friend ? { id: friend.id, name: friend.name } : null;
  },

  /** Force a connection attempt and report why it failed. Backs /try. */
  probe(query) {
    return requireEngine().probe(query);
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

  async tor() {
    return requireEngine().status();
  },

  exportIdentity() {
    const file = path.join(store.root, 'torchat-identity-backup.json');
    fs.writeFileSync(file, identity.exportBackup(), 'utf8');
    return file;
  },

  async importIdentity(file) {
    // Stop first. Restoring underneath a running engine would have it keep
    // serving the old identity's onion and write the old conversations back out
    // over the new one's.
    if (active) await active.stop();
    active = null;

    identity.importBackup(fs.readFileSync(file, 'utf8'));
    store.resetCache();

    await startEngine();
    return identity.profile();
  },
};

ipcMain.handle('torchat:call', async (_event, method, payload) => {
  const handler = handlers[method];
  if (!handler) throw new Error(`unknown call ${method}`);
  try {
    return { ok: true, value: await handler(payload) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});
