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
 */

const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');

/**
 * A first bootstrap downloads the full network consensus and relay descriptors,
 * which is megabytes. Two minutes is ample on a wired line and nowhere near
 * enough on a congested mobile connection — measured at over 120s here on a
 * phone hotspot, which is exactly the network this feature exists for. Progress
 * is logged throughout, so a long wait looks like progress rather than a hang.
 */
const BOOTSTRAP_TIMEOUT_MS = 300000;
const CONTROL_TIMEOUT_MS = 20000;

/** Tor is slow. Circuits take seconds to build; onion rendezvous takes longer. */
const DIAL_TIMEOUT_MS = 90000;

const SOCKS_VERSION = 0x05;
const SOCKS_CONNECT = 0x01;
const SOCKS_DOMAIN = 0x03;

const SOCKS_ERRORS = {
  1: 'general failure',
  2: 'connection not allowed',
  3: 'network unreachable',
  4: 'host unreachable — the onion service is probably offline',
  5: 'connection refused',
  6: 'TTL expired',
  7: 'command not supported',
  8: 'address type not supported',
};

// --- finding tor ----------------------------------------------------------

/**
 * Somewhere to find a tor binary, in order of preference.
 *
 * Tor Browser is the way most people already have one, and its bundled binary
 * works perfectly well driven by hand — we just never launch the browser.
 */
function candidatePaths() {
  const exe = process.platform === 'win32' ? 'tor.exe' : 'tor';
  const home = os.homedir();
  const list = [];

  if (process.env.TORCHAT_TOR) list.push(process.env.TORCHAT_TOR);

  // What `npm install` fetched. First choice, so a clean clone works with no
  // setup and without depending on whatever Tor the machine happens to have.
  list.push(path.join(__dirname, '..', '..', 'vendor', 'tor', 'tor', exe));

  if (process.platform === 'win32') {
    const roots = [
      path.join(home, 'Desktop', 'Tor Browser'),
      path.join(process.env.LOCALAPPDATA || '', 'Tor Browser'),
      path.join(process.env.PROGRAMFILES || '', 'Tor Browser'),
      path.join(home, 'Downloads', 'tor'),
    ];
    for (const root of roots) {
      if (!root) continue;
      list.push(path.join(root, 'Browser', 'TorBrowser', 'Tor', exe));
      list.push(path.join(root, exe));
    }
  } else {
    list.push('/usr/bin/tor', '/usr/local/bin/tor', '/opt/homebrew/bin/tor');
    list.push(path.join(home, '.local', 'bin', 'tor'));
  }

  return list;
}

/** @returns {string|null} path to a usable tor binary */
function find() {
  for (const candidate of candidatePaths()) {
    try {
      if (candidate && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      /* unreadable path, keep looking */
    }
  }

  // Last resort: whatever is on PATH. spawn resolves it, so existence is only
  // proven when we actually try to run it.
  return process.platform === 'win32' ? null : 'tor';
}

function installHint() {
  if (process.platform === 'win32') {
    return [
      'Tor is not installed. Two ways to fix that:',
      '',
      '  1. Install Tor Browser from https://www.torproject.org/download/',
      '     TorChat finds its bundled tor.exe automatically and never opens',
      '     the browser itself.',
      '',
      '  2. Or download the "Tor Expert Bundle" from the same page, unzip it,',
      '     and point TorChat at it:  set TORCHAT_TOR=C:\\path\\to\\tor.exe',
    ];
  }
  return [
    'Tor is not installed. Install it with your package manager:',
    '  apt install tor      (Debian/Ubuntu)',
    '  brew install tor     (macOS)',
    'Then restart TorChat.',
  ];
}

// --- a minimal SOCKS5 client ---------------------------------------------

/**
 * Open a connection through Tor's SOCKS port.
 *
 * The address is sent as a *domain name*, not an IP, which matters for more than
 * convenience: it means Tor resolves the .onion inside the network and this
 * machine never performs a lookup that could leak who we are trying to reach.
 * Resolving locally first would defeat the entire point.
 */
function socksConnect(socksPort, host, port, timeoutMs = DIAL_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: socksPort });
    let settled = false;

    const fail = (message, code = 'ETORDIAL') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
      const error = new Error(message);
      error.code = code;
      reject(error);
    };

    const timer = setTimeout(
      () => fail(`tor did not answer within ${Math.round(timeoutMs / 1000)}s`, 'ETIMEDOUT'),
      timeoutMs
    );

    socket.on('error', (err) => fail(`socks: ${err.message}`, err.code));
    socket.on('close', () => fail('tor closed the connection during the handshake'));

    /**
     * Read exactly `n` bytes, leaving anything beyond them untouched.
     *
     * This is why the socket is never put in flowing mode: Tor routinely
     * delivers the peer's first frame in the same segment as the SOCKS reply,
     * and that frame is the handshake's opening move. A 'data' listener would
     * hand us those bytes with no way to give them back — the connection would
     * then wait forever for a `hello` that had already arrived, looking exactly
     * like an unreachable peer. Reading precise amounts in paused mode leaves
     * the remainder in the stream's own buffer, where the caller's handler picks
     * it up the moment it attaches.
     */
    const readExactly = (n) =>
      new Promise((done) => {
        const attempt = () => {
          if (settled) return;
          const chunk = socket.read(n);
          if (chunk) return done(chunk);
          socket.once('readable', attempt);
        };
        attempt();
      });

    socket.on('connect', async () => {
      try {
        // Version 5, one method offered, "no authentication".
        socket.write(Buffer.from([SOCKS_VERSION, 0x01, 0x00]));

        const greeting = await readExactly(2);
        if (settled) return;
        if (greeting[0] !== SOCKS_VERSION || greeting[1] !== 0x00) {
          return fail('tor refused the SOCKS handshake');
        }

        const name = Buffer.from(host, 'utf8');
        if (name.length > 255) return fail('onion address is too long');

        const request = Buffer.alloc(7 + name.length);
        request.writeUInt8(SOCKS_VERSION, 0);
        request.writeUInt8(SOCKS_CONNECT, 1);
        request.writeUInt8(0x00, 2); // reserved
        request.writeUInt8(SOCKS_DOMAIN, 3);
        request.writeUInt8(name.length, 4);
        name.copy(request, 5);
        request.writeUInt16BE(port, 5 + name.length);
        socket.write(request);

        const head = await readExactly(4); // version, status, reserved, type
        if (settled) return;
        if (head[0] !== SOCKS_VERSION) return fail('bad SOCKS reply');

        const status = head[1];
        if (status !== 0x00) {
          return fail(`tor could not connect: ${SOCKS_ERRORS[status] || `code ${status}`}`);
        }

        // The bound address varies in length by type and is of no use to us,
        // but it has to be consumed to leave the stream at the tunnelled bytes.
        const type = head[3];
        let addressBytes;
        if (type === 0x01) addressBytes = 4;
        else if (type === 0x04) addressBytes = 16;
        else if (type === SOCKS_DOMAIN) {
          const length = await readExactly(1);
          if (settled) return;
          addressBytes = length[0];
        } else return fail('bad SOCKS address type');

        await readExactly(addressBytes + 2); // address plus the bound port
        if (settled) return;

        settled = true;
        clearTimeout(timer);
        socket.removeAllListeners('error');
        socket.removeAllListeners('close');
        socket.removeAllListeners('readable');

        resolve(socket);
      } catch (err) {
        fail(`socks: ${err.message}`);
      }
    });
  });
}

// --- the control port -----------------------------------------------------

/**
 * A single control connection, kept open for the process lifetime.
 *
 * Onion services created without the Detach flag die with the connection that
 * made them, which is precisely what we want: quitting TorChat should take the
 * service down rather than leave it advertised and unanswered.
 */
class Control extends EventEmitter {
  constructor(port) {
    super();
    this.port = port;
    this.socket = null;
    this.buffer = '';
    this.waiting = [];
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

    // A reply ends with a line like "250 OK" — status, space, text. Continuation
    // lines use "250-" or "250+", so the space is what marks the end.
    let match;
    while ((match = this.buffer.match(/^([\s\S]*?)(\d{3}) ([^\r\n]*)\r?\n/))) {
      const [full, body, status, tail] = match;
      this.buffer = this.buffer.slice(full.length);

      const lines = `${body}${status} ${tail}`.split(/\r?\n/).filter(Boolean);

      // 650 is an asynchronous event, not an answer to anything. Letting it
      // consume a waiting slot would resolve whichever command happened to be
      // in flight with the text of an unrelated notification — and once the
      // queue is off by one, every later reply belongs to the wrong caller.
      if (status === '650') {
        this.emit('event', lines);
        continue;
      }

      const pending = this.waiting.shift();
      if (!pending) continue;

      if (status.startsWith('2')) pending.resolve(lines);
      else pending.reject(new Error(`tor control said: ${status} ${tail}`));
    }
  }

  send(command) {
    return new Promise((resolve, reject) => {
      if (!this.socket) return reject(new Error('control port is not connected'));

      const timer = setTimeout(
        () => reject(new Error(`tor did not answer "${command.split(' ')[0]}"`)),
        CONTROL_TIMEOUT_MS
      );
      const settle = (fn) => (value) => {
        clearTimeout(timer);
        fn(value);
      };

      this.waiting.push({ resolve: settle(resolve), reject: settle(reject) });
      this.socket.write(`${command}\r\n`);
    });
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

// --- picking ports --------------------------------------------------------

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

// --- the service ----------------------------------------------------------

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
  }

  log(text) {
    this.emit('log', text);
  }

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

    this.log('tor: starting (first run can take a minute)...');

    this.process = spawn(binary, ['-f', torrc], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    await this._awaitBootstrap();
    await this._openControl();

    // Belt and braces alongside TAKEOWNERSHIP: an orphaned tor keeps an onion
    // address published that nothing answers, which looks to a friend exactly
    // like being ignored.
    this._onExit = () => this.stop();
    process.once('exit', this._onExit);
    process.once('SIGINT', this._onExit);
    process.once('SIGTERM', this._onExit);

    this.ready = true;
    return this;
  }

  _awaitBootstrap() {
    return new Promise((resolve, reject) => {
      let settled = false;
      let output = '';

      const done = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
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

      this.process.stdout.on('data', onChunk);
      this.process.stderr.on('data', onChunk);

      this.process.once('error', (err) =>
        done(Object.assign(new Error(`could not run tor: ${err.message}`), { code: 'ENOTOR' }))
      );
      this.process.once('exit', (code) =>
        done(new Error(`tor exited with code ${code} before it was ready`))
      );
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

  /**
   * Publish an onion service pointing at our local listener.
   *
   * The key is returned on first creation and stored by the caller, because the
   * onion address is derived from it — losing it means a new address and every
   * friend's card going stale.
   *
   * @returns {Promise<{address:string, key:string}>}
   */
  async publish(localPort, virtualPort = localPort) {
    const spec = this.onionKey ? this.onionKey : 'NEW:ED25519-V3';
    const lines = await this.control.send(
      `ADD_ONION ${spec} Port=${virtualPort},127.0.0.1:${localPort}`
    );

    let serviceId = null;
    let key = this.onionKey;

    for (const line of lines) {
      const id = line.match(/ServiceID=([a-z2-7]+)/i);
      if (id) serviceId = id[1];
      const priv = line.match(/PrivateKey=(\S+)/i);
      if (priv) key = priv[1];
    }

    if (!serviceId) throw new Error('tor did not return an onion address');

    this.address = `${serviceId}.onion`;
    this.onionKey = key;

    // ADD_ONION returns as soon as the service exists locally, but nobody can
    // reach it until its descriptor has been uploaded to the directory hidden
    // service directories. That takes tens of seconds, and announcing the
    // address before then hands friends something that fails with "TTL
    // expired" — measured here, and indistinguishable from being offline.
    const published = await this._awaitDescriptor(serviceId);
    this.published = published;

    this.log(
      published
        ? `tor: reachable at ${this.address}:${virtualPort}`
        : `tor: published ${this.address}:${virtualPort}, still propagating`
    );

    return { address: this.address, key, published };
  }

  /**
   * Wait for tor to report the descriptor uploaded.
   *
   * Resolves false rather than throwing on timeout: the service usually becomes
   * reachable shortly afterwards anyway, and refusing to start over a slow
   * upload would be worse than starting with an honest caveat.
   */
  async _awaitDescriptor(serviceId, timeoutMs = 120000) {
    try {
      await this.control.send('SETEVENTS HS_DESC');
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
        for (const line of lines) {
          if (/HS_DESC\s+UPLOADED\s/.test(line) && line.includes(serviceId)) {
            return finish(true);
          }
        }
      };

      this.control.on('event', onEvent);
      this.log('tor: waiting for the onion descriptor to publish...');
    });

    try {
      await this.control.send('SETEVENTS');
    } catch {
      /* nothing further depends on unsubscribing */
    }

    return uploaded;
  }

  /** Open a connection to a peer's onion address. */
  dial(host, port, timeoutMs = DIAL_TIMEOUT_MS) {
    if (!this.ready) {
      const error = new Error('tor is not running');
      error.code = 'ENOTOR';
      return Promise.reject(error);
    }
    return socksConnect(this.socksPort, host, port, timeoutMs);
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

    if (this.process) {
      try {
        this.process.kill();
      } catch {
        /* already dead */
      }
      this.process = null;
    }
  }
}

/** Does this look like a v3 onion address? 56 base32 chars plus the suffix. */
function isOnion(host) {
  return /^[a-z2-7]{56}\.onion$/i.test(String(host || ''));
}

module.exports = {
  Tor,
  find,
  isOnion,
  installHint,
  socksConnect,
  Control,
  DIAL_TIMEOUT_MS,
};
