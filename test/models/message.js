'use strict';

/**
 * The delivery contract, which cost a bug to get right.
 *
 * `sent` only ever meant the socket accepted the bytes. Treating it as delivery
 * meant a message written into a circuit that died a moment later was never
 * retried and never reported — it simply vanished. Only an ack may set
 * `delivered`, and everything short of that is still owed a retry.
 */

const Message = require('../../src/models/message');
const { suite } = require('../../scripts/harness');

const { check, run } = suite();

run(() => {
  // --- composing ----------------------------------------------------------

  {
    const m = Message.compose('hello');
    check('a composed message is ours', m.mine === true);
    check('and starts queued', m.state === Message.State.QUEUED);
    check('and has an id', typeof m.id === 'string' && m.id.length > 0);
    check('and is stamped', m.ts > 0);
    check('two messages get different ids', Message.compose('a').id !== Message.compose('a').id);
    check('a long body is clamped', Message.compose('x'.repeat(9000)).body.length === Message.MAX_BODY);
  }

  // --- receiving ----------------------------------------------------------

  {
    const m = Message.fromFrame({ id: 'abc', ts: 1234, body: 'hi' });
    check('a received message is not ours', m.mine === false);
    check('and is marked received', m.state === Message.State.RECEIVED);
    check('and keeps their id', m.id === 'abc');
    check('and keeps their timestamp', m.ts === 1234);
    check('a missing body becomes empty', Message.fromFrame({ id: 'a' }).body === '');
    check('a missing timestamp becomes now', Message.fromFrame({ id: 'a' }).ts > 0);
    check(
      'an overlong body from a peer is clamped',
      Message.fromFrame({ id: 'a', body: 'x'.repeat(9000) }).body.length === Message.MAX_BODY
    );
  }

  // --- ids ----------------------------------------------------------------

  check('an overlong peer id is clamped', Message.idFrom('x'.repeat(500)).length === Message.MAX_ID);
  check('a missing peer id is generated', Message.idFrom(undefined).length > 0);
  check('a usable peer id survives', Message.idFrom('abc') === 'abc');

  // --- the contract -------------------------------------------------------

  check('a queued message awaits ack', Message.isAwaitingAck({ mine: true, state: 'queued' }));
  check('a sent message still awaits ack', Message.isAwaitingAck({ mine: true, state: 'sent' }));
  check('a delivered message does not', !Message.isAwaitingAck({ mine: true, state: 'delivered' }));
  check('their message never awaits our ack', !Message.isAwaitingAck({ mine: false, state: 'received' }));

  // --- the wire form ------------------------------------------------------

  {
    const frame = Message.toFrame({ id: 'i', ts: 2, body: 'b', mine: true, state: 'queued' });
    check('the wire form is a msg', frame.t === 'msg');
    check('and carries the payload', frame.id === 'i' && frame.ts === 2 && frame.body === 'b');
    check('and no local bookkeeping', !('mine' in frame) && !('state' in frame));
  }
});
