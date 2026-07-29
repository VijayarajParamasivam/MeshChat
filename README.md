# TorChat

[![ci](https://github.com/VijayarajParamasivam/TorChat/actions/workflows/ci.yml/badge.svg)](https://github.com/VijayarajParamasivam/TorChat/actions/workflows/ci.yml)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

Peer-to-peer chat where every connection is a Tor onion service. No accounts, no
servers, no company in the middle — and no IP address of yours is ever published,
sent, or dialled.

You exchange one contact code with a friend, out of band, and after that either
of you can reach the other from any network on earth: home wifi, office, mobile
data behind carrier-grade NAT. No port forwarding, no relay server, no signup.

> **Read this first.** TorChat is a personal project, not an audited product,
> and it needs a terminal and Node.js to run. There is no installer to download
> yet. If that is not for you, stop here — no hard feelings.

---

## Contents

**Getting started**
- [Before you begin](#before-you-begin)
- [Install](#install)
- [Try it by yourself first](#try-it-by-yourself-first) ← start here
- [Chat with a real friend](#chat-with-a-real-friend)
- [Commands](#commands)
- [When something goes wrong](#when-something-goes-wrong)

**Understanding it**
- [How it works](#how-it-works)
- [Why onion services](#why-onion-services)
- [Privacy and security](#privacy-and-security)
- [Where your data lives](#where-your-data-lives)

**Working on it**
- [Configuration](#configuration)
- [Development](#development)
- [Licence](#licence)

---

## Before you begin

You need three things:

| | |
| --- | --- |
| **Node.js 20 or newer** | Check with `node --version`. Get it from [nodejs.org](https://nodejs.org/). |
| **Git** | Check with `git --version`. |
| **A supported machine** | Windows, macOS, or Linux on x86. See the note below for ARM. |

Set expectations before you start, so nothing looks broken when it isn't:

- **The install downloads about 500 MB.** Electron is ~430 MB of that, Tor ~70 MB.
- **The first launch takes 30 seconds or more** while Tor connects to its network.
  Later launches are much faster.
- **After that, your address needs up to a minute** to become reachable.

**On ARM Linux** (Raspberry Pi, ARM VPS) the Tor Project publishes no build we can
download, so install Tor yourself and point TorChat at it:

```bash
sudo apt install tor
export TORCHAT_TOR=/usr/bin/tor
```

## Install

```bash
git clone https://github.com/VijayarajParamasivam/TorChat.git
cd TorChat
npm install
```

`npm install` fetches Tor for your platform and checks it against a pinned
SHA-256 before unpacking. There is nothing else to configure and nothing to sign
up for.

If the Tor download fails, the install still succeeds — retry it on its own with
`npm run get-tor`.

## Try it by yourself first

**TorChat needs two people to be interesting, so start by being both of them.**
You can run a second, completely separate identity on the same machine — its own
keys, its own friend list, its own onion address. This is the fastest way to see
the whole thing work without coordinating with anyone.

**Open two terminals**, both in the `TorChat` folder.

**Terminal 1** — this is "you":

```bash
npm start
```

**Wait until it says it is reachable** before continuing. You will see the CRT
terminal boot, ask you for a handle, and then report your onion address. Type
`/tor` any time to check.

> **Why wait?** Each instance runs its own Tor, and two of them starting from
> scratch at the same time compete for your connection. Starting them one after
> the other is much more reliable — especially on a slow link, where two
> simultaneous first-time starts can time out.

**Terminal 2** — this is your "friend":

```bash
npm run start:b
```

Give it a different handle. Now connect the two windows:

1. In **window 1**, type `/copy` — your contact code goes to the clipboard
2. In **window 2**, type `/paste` — it reads the code and dials you
3. Wait for `connected to …`, then `/chat <handle>` in either window
4. Type anything. It travels out of one window, through Tor, and into the other.

That is the entire app. When you are done, `/quit` both.

## Chat with a real friend

Same idea, one machine each. **Only one of you needs to do the adding.**

**You:**

```
/card
```

Copy the whole `TORCHAT1.…` code — it is long — and send it to them however you
like: WhatsApp, email, a text, read aloud over the phone. The code contains no IP
address and reveals nothing about where you are.

**Them:**

```
/add <the code you sent>
```

That is it. When they dial in and prove who they are, you accept them
automatically, because the only way they could know your address is that you
gave it to them.

Then either of you: `/chat <their handle>` and type.

**Both of you must be running the same version.** The handshake changed recently,
and older builds are rejected with `peer could not prove it owns that ID` — which
reads like a security warning but just means "one of you needs to `git pull`".

## Commands

Anything that isn't a slash command is sent to whoever you're chatting with.

| Command | What it does |
| --- | --- |
| `/help` | List every command |
| `/who` | Your handle, ID and data directory |
| `/me <name>` | Change your display name |
| `/sigil <char>` | Change your one-character sigil |
| `/card` | Print your contact code |
| `/copy` | Copy your contact code to the clipboard |
| `/add <code>` | Add a friend from their code |
| `/paste` | Add a friend from a code already on your clipboard |
| `/forget <who>` | Remove a friend |
| `/friends` | Who you know, and who is online |
| `/chat <who>` | Open a conversation |
| `/leave` | Close the conversation |
| `/tor` | Your onion address and whether it is reachable |
| `/try <who>` | Force a connection attempt and show why it failed |
| `/export` | Write an identity backup file |
| `/import <path>` | Restore an identity backup |
| `/clear` | Wipe the screen |
| `/quit` | Exit |

`<who>` accepts a display name, a full TorChat ID, or a unique fragment of one.

**Message marks:**

| Mark | Meaning |
| --- | --- |
| `[~]` | Queued here — no live connection |
| `[>]` | Written to the circuit, not yet confirmed |
| `[ok]` | Confirmed by their app |

Anything not yet `[ok]` is resent automatically the next time you connect, so a
dropped circuit costs a retry rather than the message.

## When something goes wrong

**It has been sitting at "waking the node" for a while.**
Normal on first launch. Tor is downloading the network directory, which is a few
megabytes. Give it 30–60 seconds. The log shows progress as it goes.

**`/tor` says "published, still propagating".**
Your address exists but the network hasn't finished learning about it. Wait a
minute. Friends can't reach you until it says reachable.

**`/try` says they're not running it.**
That is usually exactly what it means. An onion service only answers while the
app is open — there is no router, firewall or ISP involved on either side, so if
a dial fails, they almost certainly don't have TorChat running.

**`peer could not prove it owns that ID`.**
You are on different versions. Both `git pull`, then restart.

**`tor is not installed`.**
The download during `npm install` failed, or you're on a platform with no build.
Retry with `npm run get-tor`, or install Tor yourself and set `TORCHAT_TOR` to
its path.

**Two instances and one of them won't start.**
Start them one at a time and let the first finish before launching the second.
Two first-time Tor bootstraps competing for one connection is slow enough to
time out.

**My address changed and my friends can't reach me.**
The onion key in your data directory was lost. Send them a new `/card`, and use
`/export` next time — it backs up your address as well as your identity.

## How it works

**Your identity** is an Ed25519 key pair generated on your machine. Your TorChat
ID is a hash of the public half — `TOR-4K7P-9XQ2-M3TV` — so nobody can claim your
ID without your private key. There is no registry to check it against and none is
needed.

**Your address** is a v3 onion service. Reaching you means building a circuit to
it: six relays, none of which knows both ends. The address is derived from a key,
so it says nothing about where you are.

**Your contact card** carries your ID, both public keys, your display name and
your onion address, signed so a card altered in transit is rejected.

**Every connection** runs a nonce challenge in both directions: each side sends a
random nonce and must return a signature over the other's, bound to both
identities and to the protocol. Holding somebody's public card gets you nowhere —
you'd need their private key. X25519 ECDH then derives a shared key, and every
frame after that is AES-256-GCM.

The encryption does not depend on Tor keeping any promises. A hostile relay
carrying your traffic sees what an eavesdropper on a LAN cable sees: sealed bytes.

### One rule the transport imposes

Tor silently discards anything an onion service writes into a rendezvous stream
before the dialler's end of it is joined — and the write still reports success.
Measured on a live circuit: a marker written on accept never arrived at all,
while the same marker written four seconds later arrived in 380 ms.

So the handshake is **ordered**: whoever dialled speaks first, and the side that
accepted stays quiet until spoken to. Symmetric in content, not in timing.
`Link._sendHello` in `src/core/transport.js` carries the measurement, and
`test/core/transport.js` pins the rule.

## Why onion services

TorChat used to try very hard to connect two machines directly. It asked routers
for port mappings over UPnP and NAT-PMP, opened IPv6 firewall pinholes over UPnP
IGDv2 and PCP, punched UDP holes on three ports at once with clock-aligned
windows, and fell back to TCP simultaneous open. Around 2,700 lines of it.

All of it existed to make one thing possible: an **inbound** connection. And every
one of those techniques can be defeated by a mobile carrier that simply drops
unsolicited packets at its core, far upstream of anything you can configure. Two
people on mobile data could not reach each other by any of them.

An onion service never needs an inbound connection. Tor dials **out** from both
ends and they meet at a rendezvous point — and outbound is the one thing every
network on earth permits, because otherwise nothing would work at all. It is the
same reason WhatsApp works everywhere; it just doesn't need WhatsApp's servers.

So the traversal code is gone. One path, no fallbacks, nothing to diagnose.

**The trade, stated honestly.** This is not host-free. Tor is thousands of
volunteer relays and nine hardcoded directory authorities — real infrastructure
nobody here owns. What survives is the property that actually matters: none of it
can read your messages or work out who is talking to whom.

It is also slower. A circuit takes seconds to build where a direct dial took
milliseconds, including to a laptop in the same room. That was the deliberate
choice: one path that always works beats six that sometimes do.

## Privacy and security

These are the specific claims, and each is enforced in code rather than by
convention:

- **Your card contains one onion address and nothing else.** There is no branch
  that could leak an IP, because there is no IP in the program to leak.
- **The listener binds `127.0.0.1` only,** so nothing but your own Tor can connect
  to it. Binding a real interface would accept direct connections and give away
  the address the onion exists to keep private.
- **IP endpoints sent by a peer are discarded on arrival,** not deprioritised — an
  old build or a hostile peer cannot get you to dial one.
- **Onion addresses leave as domain names** in the SOCKS5 request, so Tor resolves
  them inside the network. An IP there would mean your machine was resolving
  `.onion` addresses locally and leaking who it is contacting.
- **Nothing is recorded about where an inbound peer came from.** Over Tor the
  remote address is always `127.0.0.1` — your own Tor handing the connection over.
- **Tor failing to start is fatal.** Falling back to a direct connection would
  publish exactly the address this design exists to keep private.

On the cryptography:

- Contact cards are signed; an altered card is rejected, and the ID must be the
  hash of the signing key it travels with.
- The handshake proves possession, not knowledge. Proofs are bound to both
  identities and to the protocol, so a signature from one context is not valid in
  another.
- The channel key comes from X25519 ECDH; every frame after the handshake is
  AES-256-GCM with a fresh random IV.
- `identity.json` holds your private keys. **Anyone with that file is you.**

### What this does not protect against

The accurate claim is the narrow one: **no IP address of yours is ever published,
sent, or dialled.** That is enforced and tested. It is a much smaller statement
than "untrackable", and the difference matters:

- **Your ISP knows you use Tor.** TorChat speaks plain Tor — no bridges, no
  pluggable transports. The content and destination of your traffic are hidden;
  the fact that you are on Tor, and at what times, is not.
- **Your onion address is a permanent identifier.** It never rotates. Anyone
  holding your card can probe whether you are online at any moment, which leaks
  your activity pattern. Hand the same card to two people and they can prove you
  are the same person. If that address is ever tied to your name once, the link
  is permanent and retroactive.
- **Everything on your disk is plaintext.** No passphrase, no encryption at rest.
  Anyone with access to the machine reads your keys, your friend list and every
  conversation.
- **Your friend's machine.** Messages are plaintext at both ends. A screenshot, a
  compromised laptop, or simply being told is not a problem code can solve.
- **Traffic analysis by a global adversary.** Tor's own threat model applies: an
  observer who can watch both ends is out of scope for Tor and therefore out of
  scope here. The 20-second keepalive gives such an observer a regular pattern.
- **Anyone you hand your card to.** The card is a capability. Give it to the
  wrong person and they can connect to you — they learn nothing about where you
  are, but they can try.
- **It has not been audited.** It is a personal project, not a reviewed product,
  and it is young: a bug fixed recently meant the transport had never once
  completed a connection over Tor. Anonymity tools earn trust through years of
  review, and this has had none.

Sound judgement of what this is good for: a curious friend, an ISP reading your
chats, a company mining your data. Not a determined adversary with legal power
over your carrier, and not anyone with access to your computer.

## Where your data lives

Run `/who` to print the exact path. It is your Electron `userData` directory —
`%APPDATA%\torchat` on Windows, `~/Library/Application Support/torchat` on macOS,
`~/.config/torchat` on Linux — and it holds everything:

```
identity.json    your key pair — anyone with this file is you
settings.json    your onion service key — losing it means a new address
friends.json     who you know, and their onion addresses
messages/        one file per conversation, capped at 2000 messages each
tor/             Tor's own state directory
```

There is no remote copy of any of it. `/export` writes a backup containing both
your identity **and** your onion key, so a restore keeps the address your friends
already have. Guard that file the way you would a password.

## Configuration

Everything is optional.

| Variable | Effect |
| --- | --- |
| `TORCHAT_TOR` | Path to a `tor` binary to use instead of the bundled one |
| `TORCHAT_PROFILE` | Run a second, fully independent identity in its own data directory |
| `TORCHAT_SKIP_TOR` | Skip the Tor download during `npm install` |

## Development

### Tests

```bash
npm test
```

No setup beyond `npm install` — the engine and its tests use only Node built-ins,
and none of them need Tor running. 20 suites, ~400 assertions.

`test/` mirrors `src/` exactly: `test/core/tor/socks.js` covers
`src/core/tor/socks.js`, one suite per source file, with nothing else in the tree.
The runner compares both trees and reports a source nobody tests as well as a
suite whose source has gone.

| Suite | Covers |
| --- | --- |
| `test/models/*.js` | The domain entities: name clamping, the onion-only address rule, message delivery states, which of two cards wins |
| `test/core/crypto.js` | Identity derivation, signature forgery, key agreement, tampered payloads |
| `test/core/card.js` | Contact codes: round trips, four kinds of forgery, malformed input, freshness |
| `test/core/identity.js` | Key generation, profile edits, backup and restore |
| `test/core/store.js` | The outbox, direction-scoped message IDs, the droppable cache |
| `test/core/transport.js` | A full two-peer handshake over a real socket, who speaks first, bound proofs |
| `test/core/tor/*.js` | The SOCKS5 client's exact wire bytes, the control-port parser, binary discovery, onion validation |
| `test/core/roster/*.js` | Retry policy, address racing, the friend list, delivery, every privacy invariant above |
| `test/ui/*.js` | The command table in a vm sandbox — including that every engine method the UI calls actually exists |

`scripts/check-tor-pins.js` runs in CI and checks the pinned Tor checksums against
the Tor Project's release manifest. A network failure skips rather than fails.

These prove the mechanics. Whether a circuit reaches a particular friend is
something only two machines can establish.

### Layout

`src/models/` holds the domain entities — the shapes that travel between layers,
each owning its own validation. `src/core/` is the machinery that moves them
around.

```
electron/main.js            app lifecycle, IPC, engine ownership
electron/preload.js         the only bridge to the UI

src/models/profile.js       a display name and sigil, clamped
src/models/endpoint.js      an address — and the rule that only onions count
src/models/friend.js        someone you know, and which card wins
src/models/message.js       a message and its delivery states

src/core/crypto.js          signing, key agreement, sealed frames
src/core/identity.js        key generation, TorChat ID derivation
src/core/card.js            signed contact codes
src/core/transport.js       framing, handshake, encrypted channel
src/core/store.js           identity, friends and history on disk

src/core/tor/index.js       the tor process and its onion service
src/core/tor/locate.js      finding a tor binary to drive
src/core/tor/control.js     the control-port protocol
src/core/tor/socks.js       the SOCKS5 dialler

src/core/roster/index.js    the engine: lifecycle and wiring
src/core/roster/friends.js  who you know, and their addresses
src/core/roster/dialer.js   what to dial, in what order, and when to retry
src/core/roster/messages.js the delivery contract: send, ack, resend

src/ui/commands.js          every slash command, as data
src/ui/terminal.js          the CRT terminal: output, input, events

scripts/get-tor.js          fetches and verifies Tor at install time
scripts/check-tor-pins.js   verifies the pinned checksums against the manifest
scripts/second-instance.js  launches a second profile
scripts/run-tests.js        discovers and runs every suite
scripts/harness.js          the shared assertion helper
```

### Packaging

```bash
npm run build
```

Builds a Windows installer with electron-builder, bundling the vendored Tor as an
extra resource. **This has not been tested** — the config is written but nobody
has produced and run an installer from it. Other targets are not configured.

## Licence

MIT — see [LICENSE](LICENSE).
