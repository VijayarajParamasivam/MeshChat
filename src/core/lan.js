'use strict';

/**
 * Same-network discovery, so two devices on one WiFi find each other with no
 * codes, no router involvement and nothing external at all.
 *
 * Uses a multicast group rather than plain broadcast specifically because
 * several processes on one machine can each join it and all receive traffic —
 * which is what makes running two instances side by side for testing work.
 */

const dgram = require('dgram');
const { EventEmitter } = require('events');

const GROUP = '239.255.77.77';
const PORT = 47778;
const ANNOUNCE_MS = 5000;

class LanBeacon extends EventEmitter {
  constructor() {
    super();
    this.socket = null;
    this.timer = null;
    this.me = null;
  }

  /** @param {object} me { id, port } — the TCP port friends should dial. */
  start(me) {
    this.me = me;

    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.socket = socket;

    socket.on('error', (err) => {
      this.emit('log', `lan discovery unavailable: ${err.message}`);
      this.stop();
    });

    socket.on('message', (msg, remote) => {
      let announcement;
      try {
        announcement = JSON.parse(msg.toString('utf8'));
      } catch {
        return;
      }

      if (announcement.m !== 'meshchat' || !announcement.id) return;
      if (announcement.id === this.me.id) return;

      this.emit('peer', {
        id: announcement.id,
        host: remote.address,
        port: Number(announcement.port),
      });
    });

    socket.bind(PORT, () => {
      try {
        socket.addMembership(GROUP);
        socket.setMulticastTTL(1);
        socket.setMulticastLoopback(true);
      } catch (err) {
        this.emit('log', `lan discovery unavailable: ${err.message}`);
        return;
      }

      this.announce();
      this.timer = setInterval(() => this.announce(), ANNOUNCE_MS);
    });
  }

  announce() {
    if (!this.socket || !this.me) return;
    const payload = Buffer.from(
      JSON.stringify({ m: 'meshchat', id: this.me.id, port: this.me.port })
    );
    this.socket.send(payload, PORT, GROUP, () => {});
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
    if (this.socket) {
      try {
        this.socket.close();
      } catch {
        /* already closed */
      }
      this.socket = null;
    }
  }
}

module.exports = { LanBeacon, GROUP, PORT };
