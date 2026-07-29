# TorChat

[![ci](https://github.com/VijayarajParamasivam/TorChat/actions/workflows/ci.yml/badge.svg)](https://github.com/VijayarajParamasivam/TorChat/actions/workflows/ci.yml)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

Peer-to-peer chat where every connection is a Tor onion service. No accounts, no
directory, no company in the middle — and no IP address of yours is ever
published, sent, or dialled.

```bash
git clone https://github.com/VijayarajParamasivam/TorChat.git
cd TorChat
npm install
npm start
```

`npm install` downloads Tor for your platform and verifies it against a pinned
checksum. There is nothing else to configure. The first launch asks for a handle,
publishes your onion service, and you can chat.

## Contents

- [What this is](#what-this-is)
- [Requirements](#requirements)
- [Using it](#using-it)
- [How it works](#how-it-works)
- [Why onion services](#why-onion-services)
- [Privacy and security](#privacy-and-security)
- [Configuration](#configuration)
- [Where your data lives](#where-your-data-lives)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Licence](#licence)

## What this is

A desktop chat app for a handful of people who already know each other. You
exchange a contact code once, out of band, and after that either of you can
reach the other from any network, including mobile data behind carrier-grade
NAT — without port forwarding, a relay server, or an account anywhere.

**What it is not.** It is not a Signal replacement and it has not been audited.
There are no group chats, no attachments, no voice or video, and no message
history sync between your own devices. If your friend's app is closed, your
message waits on your machine until they open it. See
[the threat model](#what-this-does-not-protect-against) for the honest limits.

## Requirements

- **Node.js 20 or newer**
- **Windows, macOS, or Linux on x86.** `npm install` fetches an official Tor
  expert bundle for `win32` (x64/ia32), `darwin` (x64/arm64) and `linux`
  (x64/ia32).

The Tor Project publishes no expert bundle for ARM Linux, so on a Raspberry Pi
or an ARM VPS, install Tor yourself and point TorChat at it:

```bash
sudo apt install tor
export TORCHAT_TOR=/usr/bin/tor
```

If you already have Tor Browser installed, TorChat finds its bundled `tor`
binary automatically and never opens the browser.

## Using it

To add a friend, run `/card`, send the code however you like — WhatsApp, email, a
sticky note — and they run `/add <code>`. **Only one of you needs to do it.** When
they dial in and prove who they are, you accept them automatically, since the
only way they could know your address is that you gave them the card.

Anything that isn't a slash command is sent to whoever you're chatting with.

### Commands

| Command | What it does |
| --- | --- |
| `/help` | List every command |
| `/who` | Your handle, ID and data directory |
| `/me <name>` | Change your display name (24 chars) |
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

### Message states

| Mark | Meaning |
| --- | --- |
| `[~]` | Queued on your machine — no live connection |
| `[>]` | Written to the circuit, not yet acknowledged |
| `[ok]` | Acknowledged by their app |

A message stays in the outbox until it is acknowledged, so anything written into
a circuit that dies is resent on the next connection rather than lost. Their app
discards a copy it already has.

## How it works

**Your identity** is an Ed25519 key pair generated on your machine. Your TorChat
ID is a hash of the public half — `TOR-4K7P-9XQ2-M3TV` — so nobody can claim your
ID without your private key. There is no registry to check it against and none is
needed.

**Your address** is a v3 onion service. Tor publishes it, and reaching you means
building a circuit to it: six relays, none of which knows both ends. The address
is derived from a key, so it says nothing about where you are. Friends dial a
fixed virtual port (`47777`) that exists only inside Tor and never has to be free
on your machine.

**Your contact card** carries your ID, both public keys, your display name and
your onion address, signed so that a card altered in transit is rejected. It is
the only thing you ever hand over.

**Every connection** runs a nonce challenge in both directions: each side sends a
random nonce and must return a signature over the other's, bound to both
identities and to the protocol. Holding somebody's public card gets you nowhere —
you would need their private key. X25519 ECDH then derives a shared key and every
frame after that is AES-256-GCM.

The encryption does not depend on Tor keeping any promises. A hostile relay
carrying your traffic sees what an eavesdropper on a LAN cable sees: sealed bytes.

**Connections are symmetric.** Either side may dial the other and whoever gets
there first wins; a peer that dials in and proves its identity is accepted
automatically. When a friend is offline, TorChat retries every 30 seconds, backing
off to five minutes.

### One rule the transport imposes

Tor silently discards anything an onion service writes into a rendezvous stream
before the dialler's end of it is joined — and the write still reports success.
Measured on a live circuit: a marker written on accept never arrived at all,
while the same marker written four seconds later arrived in 380 ms.

So the handshake is **ordered**: whoever dialled speaks first, and the side that
accepted stays quiet until spoken to. It is symmetric in content, not in timing.
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
  remote address is always `127.0.0.1` — your own Tor handing the connection
  over — so there is nothing true to learn.
- **Tor failing to start is fatal.** Falling back to a direct connection would
  publish exactly the address this design exists to keep private.

On the cryptography:

- Contact cards are signed; an altered card is rejected, and the ID must be the
  hash of the signing key it travels with.
- The handshake proves possession, not knowledge. Proofs are bound to both
  identities and to the protocol, so a signature from one context is not valid in
  another.
- The channel key comes from X25519 ECDH between the two peers; every frame after
  the handshake is AES-256-GCM with a fresh random IV.
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
  conversation. Full-disk encryption is your business, not this app's.
- **Your friend's machine.** Messages are plaintext at both ends. A screenshot, a
  compromised laptop, or simply being told is not a problem code can solve.
- **Traffic analysis by a global adversary.** Tor's own threat model applies: an
  observer who can watch both ends is out of scope for Tor and therefore out of
  scope here. The 20-second keepalive gives such an observer a regular pattern to
  work with.
- **Anyone you hand your card to.** The card is a capability. Give it to the
  wrong person and they can connect to you — they learn nothing about where you
  are, but they can try.
- **It has not been audited.** It is a personal project, not a reviewed product,
  and it is young: a bug fixed in the current release meant the transport had
  never once completed a connection over Tor. Anonymity tools earn trust through
  years of review, and this has had none.

Sound judgement of what this is good for: a curious friend, an ISP reading your
chats, a company mining your data. Not a determined adversary with legal power
over your carrier, and not anyone with access to your computer.

## Configuration

Everything is optional.

| Variable | Effect |
| --- | --- |
| `TORCHAT_TOR` | Path to a `tor` binary to use instead of the bundled one |
| `TORCHAT_PROFILE` | Run a second, fully independent identity in its own data directory |
| `TORCHAT_SKIP_TOR` | Skip the Tor download during `npm install` |

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

## Development

### Tests

```bash
npm test
```

No setup beyond `npm install` — the engine and its tests use only Node built-ins,
and none of them need Tor running. 20 suites, ~400 assertions.

Every suite sits at the mirror of the file it covers, so there is never a
question of where a test belongs or whether one exists:

| Suite | Covers |
| --- | --- |
| `test/models/*.js` | The domain entities: name clamping, the onion-only address rule, message delivery states, which of two cards wins |
| `test/core/crypto.js` | Identity derivation, signature forgery, key agreement, tampered payloads |
| `test/core/card.js` | Contact codes: round trips, four kinds of forgery, malformed input, freshness |
| `test/core/identity.js` | Key generation, profile edits, and a backup that restores your address as well as your name |
| `test/core/store.js` | The outbox, direction-scoped message IDs, the droppable cache |
| `test/core/transport.js` | A full two-peer handshake over a real socket, who speaks first, bound proofs |
| `test/core/tor/*.js` | The SOCKS5 client's exact wire bytes, the control-port parser, binary discovery, onion validation |
| `test/core/roster/*.js` | Retry policy, address racing, the friend list, delivery, and every privacy invariant above |
| `test/ui/*.js` | The command table in a vm sandbox — including that every engine method the UI calls actually exists in `main.js` |

`scripts/check-tor-pins.js` runs in CI and checks the pinned Tor checksums against
the Tor Project's release manifest. A network failure skips rather than fails —
being unable to reach the archive says nothing about whether the pins are right.

These prove the mechanics. Whether a circuit reaches a particular friend is
something only two machines can establish.

### Two instances on one machine

```bash
npm run start:b
```

Runs a second identity in a separate data directory, with its own keys, friend
list and onion address, so you can talk to yourself. There is no port to
coordinate — the local listener takes whatever the OS hands it.

### Packaging

```bash
npm run build
```

Builds a Windows installer with electron-builder, bundling the vendored Tor as an
extra resource. Other targets are not configured yet.

### Layout

`src/models/` holds the domain entities — the shapes that travel between layers,
each owning its own validation. `src/core/` is the machinery that moves them
around. Each module owns one concern, and the directories exist because the
subject matter genuinely splits along those lines rather than by size.

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

`test/` mirrors `src/` exactly: `test/core/tor/socks.js` covers
`src/core/tor/socks.js`, one suite per source file, twenty for twenty, with
nothing else in the tree. The test tooling lives in `scripts/` with the rest of
the tooling, which is what keeps that true — the runner can then compare the two
trees as a plain set difference and report both a source nobody tests and a
suite whose source has gone.

## Troubleshooting

**First launch takes about 30 seconds.** Tor downloads the network consensus and
publishes your descriptor. Progress is logged so it doesn't look hung. Later
launches are faster.

**A new onion address takes a minute to become reachable** after first publish,
while the descriptor propagates to the directory. `/tor` tells you which state
you are in.

**`/try` says they are not running it.** An onion service only answers while it is
published, and there is no router, firewall or ISP involved on either side. If a
dial fails, they almost certainly do not have TorChat open.

**`peer could not prove it owns that ID`.** You are on different versions. The
proof format is bound to both identities as of the current release; both of you
need to be on the same build.

**`tor is not installed`.** The download during `npm install` failed, or you are
on a platform with no bundled build. Retry with `npm run get-tor`, or install Tor
yourself and set `TORCHAT_TOR` to its path.

**Your address changed.** The onion key in `settings.json` was lost, so every
friend's saved card is stale. Send them a new `/card`. Use `/export` to avoid it
next time.

## Licence

MIT — see [LICENSE](LICENSE).
