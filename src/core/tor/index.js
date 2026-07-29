'use strict';

/**
 * Reaching each other over Tor, and telling each other nothing in the process.
 *
 * Everything else in this project fights the same battle: your address exists,
 * but something upstream refuses to deliver unsolicited packets to it, and on a
 * mobile carrier that refusal is absolute. An onion service sidesteps the fight
 * rather than winning it. Tor makes only *outbound* connections — to
 * introduction points, then to a rendezvous point both sides dial out to — and
 * outbound is the one thing every firewall on earth permits. Nothing ever has to
 * arrive at your address unsolicited, so nothing can be dropped.
 *
 * That single property replaces UPnP, pinholes, hole punching and port
 * forwarding at once. It is the same reason WhatsApp works everywhere: the only
 * connections are ones somebody made outward.
 *
 * The privacy is the other half. Your peer connects to an onion address, never
 * to an IP. The rendezvous point sees two circuits and cannot associate them
 * with either end, and neither friend ever learns where the other physically is.
 * The address is a public key, not a location.
 *
 * The honest trade: this is no longer host-free. Tor is thousands of volunteer
 * relays and nine hardcoded directory authorities, which is a real dependency on
 * infrastructure nobody here owns. What survives is the property that actually
 * matters — none of it can read a message or work out who is talking to whom,
 * because the frames are already sealed by the time they enter a circuit and the
 * identities are keys rather than addresses.
 *
 * Nothing is trusted on Tor's word. The Ed25519 handshake still runs inside the
 * circuit exactly as it does over TCP, so a compromised relay or a hostile exit
 * gets the same thing an eavesdropper on a LAN gets: sealed bytes.
 *
 * This file owns the tor *process*. The pieces it drives live alongside it:
 * locate.js finds a binary, control.js speaks the control port, socks.js dials.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');

const { find, installHint } = require('./locate');
const { Control } = require('./control');
const { socksConnect, DIAL_TIMEOUT_MS } = require('./socks');

/**
 * A first bootstrap downloads the full network consensus and relay descriptors,
 * which is megabytes. Two minutes is ample on a wired line and nowhere near
 * enough on a congested mobile connection — measured at over 120s here on a
 * phone hotspot, which is exactly the network this feature exists for. Progress
 * is logged throughout, so a long wait looks like progress rather than a hang.
 */
const BOOTSTRAP_TIMEOUT_MS = 300000;

/** How long to wait for the onion descriptor to reach the directories. */
const DESCRIPTOR_TIMEOUT_MS = 120000;

/** A free localhost port, so we never collide with an already-running Tor. */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/** Does this look like a v3 onion address? 56 base32 chars plus the suffix. */
function isOnion(host) {
  return /^[a-z2-7]{56}\.onion$/i.test(String(host || ''));
}

function notRunning() {
  const error = new Error('tor is not running');
  error.code = 'ENOTOR';
  return error;
}

class Tor extends EventEmitter {
  /**
   * @param {object} options
   *   dataDir     where tor keeps its state (inside the app's own store)
   *   onionKey    previously saved key, so the address survives a restart
   */
  constructor({ dataDir, onionKey = null } = {}) {
    super();
    this.dataDir = dataDir;
    this.onionKey = onionKey;
    this.process = null;
    this.control = null;
    this.socksPort = null;
    this.controlPort = null;
    this.address = null;
    this.ready = false;
    this.published = false;
  }

  log(text) {
    this.emit('log', text);
  }

  // --- lifecycle ----------------------------------------------------------

  /**
   * Launch tor and wait for it to finish bootstrapping.
   *
   * Its own DataDirectory lives under the app's store rather than the system
   * one, so TorChat never disturbs a Tor the user runs for anything else.
   */
  async start() {
    const binary = find();
    if (!binary) {
      const error = new Error('no tor binary found');
      error.code = 'ENOTOR';
      error.hint = installHint();
      throw error;
    }

    fs.mkdirSync(this.dataDir, { recursive: true });
    [this.socksPort, this.controlPort] = await Promise.all([freePort(), freePort()]);

    const torrc = this._writeTorrc();
    this.log('tor: starting (first run can take a minute)...');
    this.process = spawn(binary, ['-f', torrc], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Any failure from here on must take the process with it. A tor left alive
    // after a rejected start() is not merely a leak: it holds the lock on its
    // DataDirectory, so the *next* launch fails too, and the app never recovers
    // without someone finding the stray process by hand.
    try {
      await this._awaitBootstrap();
      await this._openControl();
    } catch (err) {
      this._killProcess();
      this.control?.close();
      this.control = null;
      throw err;
    }

    this._watchForDeath();
    this.ready = true;
    return this;
  }

  _writeTorrc() {
    const torrc = path.join(this.dataDir, 'torrc');
    fs.writeFileSync(
      torrc,
      [
        `SocksPort 127.0.0.1:${this.socksPort}`,
        `ControlPort 127.0.0.1:${this.controlPort}`,
        'CookieAuthentication 1',
        `DataDirectory ${this.dataDir}`,
        // Nothing on this machine should be able to use us as a proxy.
        'SocksPolicy accept 127.0.0.1',
        'SocksPolicy reject *',
        'Log notice stdout',
        '',
      ].join('\n'),
      'utf8'
    );
    return torrc;
  }

  /** Notice both the ways tor can die: with us, and without us. */
  _watchForDeath() {
    // Belt and braces alongside TAKEOWNERSHIP: an orphaned tor keeps an onion
    // address published that nothing answers, which looks to a friend exactly
    // like being ignored.
    this._onExit = () => this.stop();
    process.once('exit', this._onExit);
    process.once('SIGINT', this._onExit);
    process.once('SIGTERM', this._onExit);

    // Tor dying later is not hypothetical — it is killed by an OOM reaper, or a
    // user tidying up Task Manager. Without this, `ready` stayed true, every
    // dial went to a dead SOCKS port, and the resulting ECONNREFUSED was
    // reported to the user as the *friend* being offline.
    this.process.once('exit', (code) => {
      if (!this.ready) return;
      this.ready = false;
      this.log(`tor: exited unexpectedly (code ${code}) — restart torchat to reconnect`);
      this.emit('down', code);
    });
  }

  _awaitBootstrap() {
    return new Promise((resolve, reject) => {
      let settled = false;
      let output = '';

      const detach = () => {
        this.process.stdout.off('data', onChunk);
        this.process.stderr.off('data', onChunk);
        this.process.off('error', onError);
        this.process.off('exit', onExit);

        // Still drain both pipes. Tor logs notices for as long as it runs, and
        // a pipe nobody reads fills at 64KB and blocks the writer — which would
        // wedge tor itself. Flowing with no listener discards, which is what we
        // want: `output` stops growing here rather than accumulating every log
        // line for the lifetime of the app.
        this.process.stdout.resume();
        this.process.stderr.resume();
        output = '';
      };

      const done = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        detach();
        if (err) reject(err);
        else resolve();
      };

      const timer = setTimeout(
        () => done(new Error('tor did not finish bootstrapping in time')),
        BOOTSTRAP_TIMEOUT_MS
      );

      const onChunk = (chunk) => {
        const text = chunk.toString('utf8');
        output += text;

        // Progress is genuinely slow on a first run; showing it stops the app
        // looking hung.
        for (const match of text.matchAll(/Bootstrapped (\d+)%[^\r\n]*/g)) {
          this.log(`tor: ${match[0].toLowerCase()}`);
        }
        if (/Bootstrapped 100%/.test(output)) done();
      };

      const onError = (err) =>
        done(Object.assign(new Error(`could not run tor: ${err.message}`), { code: 'ENOTOR' }));

      const onExit = (code) => done(new Error(`tor exited with code ${code} before it was ready`));

      this.process.stdout.on('data', onChunk);
      this.process.stderr.on('data', onChunk);
      this.process.once('error', onError);
      this.process.once('exit', onExit);
    });
  }

  async _openControl() {
    const cookie = fs.readFileSync(path.join(this.dataDir, 'control_auth_cookie'));
    this.control = new Control(this.controlPort);
    await this.control.connect();
    await this.control.send(`AUTHENTICATE ${cookie.toString('hex')}`);

    // Tie tor's lifetime to this control connection. Without it a crash — or any
    // exit that misses stop() — leaves tor running with the onion service still
    // published, and on Windows nothing reaps it. TAKEOWNERSHIP makes tor shut
    // itself down the moment the socket closes, however we die.
    try {
      await this.control.send('TAKEOWNERSHIP');
      // Tor's own parent-process check would otherwise still apply and race the
      // ownership we just took.
      await this.control.send('RESETCONF __OwningControllerProcess');
    } catch {
      // Older tor without TAKEOWNERSHIP: fall back to killing it in stop(),
      // which covers every orderly exit.
    }
  }

  /** Kill the tor we spawned, if it is still with us. */
  _killProcess() {
    if (!this.process) return;
    try {
      this.process.kill();
    } catch {
      /* already dead */
    }
    this.process = null;
  }

  stop() {
    this.ready = false;

    if (this._onExit) {
      process.removeListener('exit', this._onExit);
      process.removeListener('SIGINT', this._onExit);
      process.removeListener('SIGTERM', this._onExit);
      this._onExit = null;
    }

    this.control?.close();
    this.control = null;

    this._killProcess();
  }

  // --- the onion service --------------------------------------------------

  /**
   * Publish an onion service pointing at our local listener.
   *
   * The key is returned on first creation and stored by the caller, because the
   * onion address is derived from it — losing it means a new address and every
   * friend's card going stale.
   *
   * @returns {Promise<{address:string, key:string, published:boolean}>}
   */
  async publish(localPort, virtualPort = localPort) {
    const spec = this.onionKey || 'NEW:ED25519-V3';
    const lines = await this.control.send(
      `ADD_ONION ${spec} Port=${virtualPort},127.0.0.1:${localPort}`
    );

    const { serviceId, key } = this._readOnionReply(lines);
    if (!serviceId) throw new Error('tor did not return an onion address');

    this.address = `${serviceId}.onion`;
    this.onionKey = key;

    // ADD_ONION returns as soon as the service exists locally, but nobody can
    // reach it until its descriptor has been uploaded to the hidden service
    // directories. That takes tens of seconds, and announcing the address
    // before then hands friends something that fails with "TTL expired" —
    // measured here, and indistinguishable from being offline.
    this.published = await this._awaitDescriptor(serviceId);

    this.log(
      this.published
        ? `tor: reachable at ${this.address}:${virtualPort}`
        : `tor: published ${this.address}:${virtualPort}, still propagating`
    );

    return { address: this.address, key, published: this.published };
  }

  /** Pull the service id and (on first creation) the private key out of a reply. */
  _readOnionReply(lines) {
    let serviceId = null;
    let key = this.onionKey;

    for (const line of lines) {
      const id = line.match(/ServiceID=([a-z2-7]+)/i);
      if (id) serviceId = id[1];
      const priv = line.match(/PrivateKey=(\S+)/i);
      if (priv) key = priv[1];
    }

    return { serviceId, key };
  }

  /**
   * Wait for tor to report the descriptor uploaded.
   *
   * Resolves false rather than throwing on timeout: the service usually becomes
   * reachable shortly afterwards anyway, and refusing to start over a slow
   * upload would be worse than starting with an honest caveat.
   */
  async _awaitDescriptor(serviceId, timeoutMs = DESCRIPTOR_TIMEOUT_MS) {
    try {
      await this.control.subscribe('HS_DESC');
    } catch {
      return false;
    }

    const uploaded = await new Promise((resolve) => {
      const timer = setTimeout(() => finish(false), timeoutMs);

      const finish = (value) => {
        clearTimeout(timer);
        this.control.removeListener('event', onEvent);
        resolve(value);
      };

      const onEvent = (lines) => {
        const seen = lines.some(
          (line) => /HS_DESC\s+UPLOADED\s/.test(line) && line.includes(serviceId)
        );
        if (seen) finish(true);
      };

      this.control.on('event', onEvent);
      this.log('tor: waiting for the onion descriptor to publish...');
    });

    try {
      await this.control.unsubscribe('HS_DESC');
    } catch {
      /* nothing further depends on unsubscribing */
    }

    return uploaded;
  }

  // --- dialling -----------------------------------------------------------

  /** Open a connection to a peer's onion address. */
  dial(host, port, timeoutMs = DIAL_TIMEOUT_MS) {
    if (!this.ready) return Promise.reject(notRunning());
    return socksConnect(this.socksPort, host, port, timeoutMs);
  }
}

module.exports = {
  Tor,
  isOnion,
  freePort,
  find,
  installHint,
  socksConnect,
  Control,
  DIAL_TIMEOUT_MS,
};
