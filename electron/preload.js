'use strict';

/**
 * The only bridge between the UI and Node. Everything crosses as plain data
 * through a single `call` channel, so the renderer can never touch sockets,
 * keys or the filesystem directly.
 */

const { contextBridge, ipcRenderer } = require('electron');

const EVENTS = [
  'mesh:log',
  'mesh:status',
  'mesh:message',
  'mesh:delivered',
  'mesh:ready',
  'mesh:friends-changed',
  'mesh:history-changed',
];

contextBridge.exposeInMainWorld('mesh', {
  /** Invoke an engine method. Rejects with a readable message on failure. */
  async call(method, payload) {
    const result = await ipcRenderer.invoke('mesh:call', method, payload);
    if (!result.ok) throw new Error(result.error);
    return result.value;
  },

  on(event, callback) {
    if (!EVENTS.includes(event)) throw new Error(`unknown event ${event}`);
    ipcRenderer.on(event, (_e, payload) => callback(payload));
  },
});
