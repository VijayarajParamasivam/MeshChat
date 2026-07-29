'use strict';

/**
 * Tor's control port is a line protocol, and two of its rules were bugs first.
 *
 * A status code has to be anchored to the start of a line: an event reading
 * "...for 250 seconds" used to terminate the reply early and reject whoever was
 * waiting. And a command that timed out has to leave its slot in the queue so
 * its own late reply is absorbed there — removing it handed that answer to the
 * *next* caller, and from then on every reply belonged to the wrong command.
 */

const { Control } = require('../../../src/core/tor/control');
const { suite } = require('../../../scripts/harness');

const { check, run } = suite();

/** A control connection with a socket that goes nowhere. */
function offline() {
  const control = new Control(0);
  const written = [];
  control.socket = { write: (line) => written.push(line.trim()) };
  return { control, written };
}

run(async () => {
  // --- assembling replies --------------------------------------------------

  {
    const { control } = offline();
    const collected = [];
    const pending = new Promise((resolve, reject) => control.waiting.push({ resolve, reject }));
    pending.then((lines) => collected.push(...lines)).catch(() => {});

    control._onData(
      '250-ServiceID=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx\r\n' +
        '250-PrivateKey=ED25519-V3:SOMEKEYMATERIAL\r\n' +
        '250 OK\r\n'
    );
    await pending;

    check('a multi-line reply is assembled', collected.length === 3);
    check(
      'the service id is recoverable',
      /ServiceID=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx/.test(collected[0])
    );
    check('the private key is recoverable', /PrivateKey=ED25519-V3:/.test(collected[1]));
  }

  {
    const { control } = offline();
    const replies = [];
    control.waiting.push({ resolve: (lines) => replies.push(lines), reject: () => {} });
    control._onData('250-ServiceID=abc\r\n250-Note=we waited 250 seconds\r\n250 OK\r\n');

    check('a status code inside a line does not end the reply', replies.length === 1);
    check('the whole reply survives', (replies[0] || []).length === 3);
    check('nothing is left over', control.buffer === '');
  }

  {
    const { control } = offline();
    const rejected = new Promise((resolve, reject) => control.waiting.push({ resolve, reject }))
      .then(() => false)
      .catch(() => true);
    control._onData('515 Authentication failed\r\n');
    check('an error status rejects rather than resolves', await rejected);
  }

  // --- a reply split across packets ----------------------------------------

  {
    const { control } = offline();
    const replies = [];
    control.waiting.push({ resolve: (lines) => replies.push(lines), reject: () => {} });
    control._onData('250-One\r\n250-T');
    check('a partial reply waits', replies.length === 0);
    control._onData('wo\r\n250 OK\r\n');
    check('and completes when the rest lands', replies.length === 1 && replies[0].length === 3);
  }

  // --- events must not consume a waiting slot ------------------------------

  {
    const { control } = offline();
    const events = [];
    control.on('event', (lines) => events.push(lines));

    let answered = null;
    control.waiting.push({ resolve: (lines) => { answered = lines; }, reject: () => {} });

    control._onData('650 HS_DESC UPLOADED abc\r\n');
    check('an event is emitted', events.length === 1);
    check('and does not answer a pending command', answered === null);

    control._onData('250 OK\r\n');
    check('the command still gets its own reply', answered !== null);
  }

  // --- an abandoned slot absorbs its own late reply ------------------------

  {
    const { control } = offline();
    let secondGot = null;
    control.waiting.push({ abandoned: true, resolve: () => {}, reject: () => {} });
    control.waiting.push({ resolve: (lines) => { secondGot = lines; }, reject: () => {} });

    control._onData('250 LATE\r\n');
    check('a late reply is absorbed by its own slot', secondGot === null);

    control._onData('250 MINE\r\n');
    check('the next command still gets its own reply', /MINE/.test((secondGot || []).join('')));
  }

  // --- event subscriptions -------------------------------------------------
  //
  // SETEVENTS replaces the list rather than adding to it, so unsubscribing one
  // thing must not silently cancel everything else that asked to be told.

  {
    const { control } = offline();
    const sent = [];
    control.send = async (command) => {
      sent.push(command);
      return [];
    };

    await control.subscribe('HS_DESC');
    check('subscribing sends the set', sent[0] === 'SETEVENTS HS_DESC');

    await control.subscribe('STATUS_CLIENT');
    check('subscribing again resends everything', sent[1] === 'SETEVENTS HS_DESC STATUS_CLIENT');

    await control.unsubscribe('HS_DESC');
    check('unsubscribing keeps the others', sent[2] === 'SETEVENTS STATUS_CLIENT');

    await control.unsubscribe('STATUS_CLIENT');
    check('unsubscribing the last one clears it', sent[3] === 'SETEVENTS');
  }

  // --- sending with no connection ------------------------------------------

  {
    const control = new Control(0);
    let refused = false;
    await control.send('GETINFO version').catch(() => { refused = true; });
    check('sending without a socket is refused', refused);
  }
});
