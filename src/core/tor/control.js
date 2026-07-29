'use strict';

/**
 * Tor's control port: a line protocol for asking a running tor to do things.
 *
 * One connection is kept open for the process lifetime. Onion services created
 * without the Detach flag die with the connection that made them, which is
 * precisely what we want: quitting TorChat should take the service down rather
 * than leave it advertised and unanswered.
 */

const net = require('net');
const { EventEmitter } = require('events');

const CONTROL_TIMEOUT_MS = 20000;

/**
 * A reply ends with a line like "250 OK" — status, space, text. Continuation
 * lines use "250-" or "250+", so the space is what marks the end.
 *
 * The status must be anchored to the start of a line. Without the `m` flag and
 * the second `^`, three digits followed by a space *anywhere inside* a
 * continuation line terminated the reply early — an event line reading
 * "...for 250 seconds" would truncate the answer and reject the caller.
 */
const REPLY = /^([\s\S]*?)^(\d{3}) ([^\r\n]*)\r?\n/m;

/** 650 is an asynchronous event, not an answer to anything. */
const EVENT_STATUS = '650';

class Control extends EventEmitter {
  constructor(port) {
    super();
    this.port = port;
    this.socket = null;
    this.buffer = '';
    this.waiting = [];
    this.events = new Set();
  }

  connect() {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port: this.port });
      socket.setEncoding('utf8');
      socket.once('error', reject);
      socket.once('connect', () => {
        socket.removeListener('error', reject);
        socket.on('error', () => this._flush(new Error('control connection lost')));
        socket.on('close', () => this._flush(new Error('control connection closed')));
        socket.on('data', (chunk) => this._onData(chunk));
        this.socket = socket;
        resolve();
      });
    });
  }

  _flush(error) {
    const pending = this.waiting.splice(0);
    for (const { reject } of pending) reject(error);
  }

  _onData(chunk) {
    this.buffer += chunk;

    let match;
    while ((match = this.buffer.match(REPLY))) {
      const [full, body, status, tail] = match;
      this.buffer = this.buffer.slice(full.length);
      this._deliver(status, tail, `${body}${status} ${tail}`.split(/\r?\n/).filter(Boolean));
    }
  }

  /** Route one complete reply to whoever is owed it. */
  _deliver(status, tail, lines) {
    // Letting an event consume a waiting slot would resolve whichever command
    // happened to be in flight with the text of an unrelated notification — and
    // once the queue is off by one, every later reply belongs to the wrong
    // caller.
    if (status === EVENT_STATUS) return void this.emit('event', lines);

    const pending = this.waiting.shift();
    if (!pending) return;

    // An abandoned slot still has to be shifted off by its own late reply.
    // Removing it at timeout instead would hand this answer to the *next*
    // caller, which is the same off-by-one the event case above avoids.
    if (pending.abandoned) return;

    if (status.startsWith('2')) pending.resolve(lines);
    else pending.reject(new Error(`tor control said: ${status} ${tail}`));
  }

  send(command) {
    return new Promise((resolve, reject) => {
      if (!this.socket) return reject(new Error('control port is not connected'));

      const entry = { abandoned: false };

      const timer = setTimeout(() => {
        entry.abandoned = true;
        reject(new Error(`tor did not answer "${command.split(' ')[0]}"`));
      }, CONTROL_TIMEOUT_MS);

      const settle = (fn) => (value) => {
        clearTimeout(timer);
        fn(value);
      };

      entry.resolve = settle(resolve);
      entry.reject = settle(reject);

      this.waiting.push(entry);
      this.socket.write(`${command}\r\n`);
    });
  }

  /**
   * Subscribe to an asynchronous event class.
   *
   * SETEVENTS replaces the whole subscription list rather than adding to it, so
   * the full set is resent every time. Unsubscribing one thing must not silently
   * cancel everything else that asked to be told.
   */
  subscribe(name) {
    this.events.add(name);
    return this._sendEvents();
  }

  unsubscribe(name) {
    this.events.delete(name);
    return this._sendEvents();
  }

  _sendEvents() {
    return this.send(`SETEVENTS ${[...this.events].join(' ')}`.trim());
  }

  close() {
    try {
      this.socket?.destroy();
    } catch {
      /* already gone */
    }
    this.socket = null;
  }
}

module.exports = { Control, CONTROL_TIMEOUT_MS };
