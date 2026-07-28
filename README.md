# MeshChat

Peer-to-peer chat where every connection is a Tor onion service. No accounts, no
directory, no company in the middle — and no IP address of yours is ever
published, sent, or dialled.

```
git clone https://github.com/VijayarajParamasivam/MeshChat.git
cd MeshChat
npm install
npm start
```

`npm install` downloads Tor for your platform and verifies it against a pinned
checksum. There is nothing else to configure. First launch asks for a handle,
publishes your onion service, and you can chat.

## How it works

Your identity is an **Ed25519 key pair** generated on your machine. Your Mesh ID
is a hash of the public half, so nobody can claim your ID without your private
key. There is no registry to check it against and none is needed.

Your **address** is a v3 onion service. Tor publishes it, and reaching you means
building a circuit to it — six relays, none of which knows both ends. The address
is derived from a key, so it says nothing about where you are.

Every connection runs a **nonce challenge in both directions**: each side sends a
random nonce and must return a signature over the other's. Holding somebody's
public card gets you nowhere. Then **X25519 ECDH** derives a shared key and every
frame after that is **AES-256-GCM**.

The encryption does not depend on Tor keeping any promises. A hostile relay
carrying your traffic sees what an eavesdropper on a LAN cable sees: sealed bytes.

## Why onion services, and not direct connections

MeshChat used to try very hard to connect two machines directly. It asked routers
for port mappings over UPnP and NAT-PMP, opened IPv6 firewall pinholes over UPnP
IGDv2 and PCP, punched UDP holes on three ports at once with clock-aligned
windows, and fell back to TCP simultaneous open. Around 2,700 lines of it.

All of it existed to make one thing possible: an **inbound** connection. And every
one of those techniques can be defeated by a mobile carrier that simply drops
unsolicited packets at its core, far upstream of anything you can configure. Two
people on mobile data could not reach each other by any of them.

An onion service never needs an inbound connection. Tor dials **out** from both
ends and they meet at a rendezvous point — and outbound is the one thing every
network on earth permits, because otherwise nothing would work at all. It's the
same reason WhatsApp works everywhere; it just doesn't need WhatsApp's servers.

So the traversal code is gone. One path, no fallbacks, nothing to diagnose.

**The trade, stated honestly.** This is not host-free. Tor is thousands of
volunteer relays and nine hardcoded directory authorities — real infrastructure
nobody here owns. What survives is the property that actually matters: none of it
can read your messages or work out who is talking to whom.

It is also slower. A circuit takes seconds to build where a direct dial took
milliseconds, including to a laptop in the same room. That was the deliberate
choice: one path that always works beats six that sometimes do.

## Using it

To add a friend, run `/card`, send the code however you like, and they run
`/add <code>`. **Only one of you needs to do it** — when they dial in and prove
who they are, you accept them automatically, since the only way they could know
your address is that you gave them the card.

```
/help              all commands
/card              print your contact code
/copy              copy it to the clipboard
/add <code>        add a friend
/friends           who you know and who's online
/chat <who>        open a conversation
/tor               your onion address and whether it's reachable
/try <who>         force a connection attempt and show why it failed
/export            back up your identity
```

Anything that isn't a slash command is sent to whoever you're chatting with.
Messages show `[~]` queued, `[>]` sent, `[ok]` delivered.

### Two instances on one machine

```
npm run start:b
```

Runs a second identity in a separate data directory, with its own onion address,
for testing against yourself.

## What to expect

**First launch takes about 30 seconds.** Tor downloads the network consensus and
publishes your descriptor. Progress is logged so it doesn't look hung. Later
launches are faster.

**A friend has to be running MeshChat to be reachable.** An onion service only
answers while it's published. There is no router, firewall or ISP involved on
either side, so if `/try` fails, they are almost certainly not running it.

**A new onion address takes a minute to become reachable** after first publish,
while the descriptor propagates. `/tor` tells you which state you're in.

**Your onion address is stable.** It's derived from a key stored in your data
directory, so it survives restarts. Losing that key means a new address and every
friend's card going stale — `/export` backs it up along with your identity.

## Privacy

These are the specific claims, and each is enforced in code rather than by
convention:

- Your card contains one onion address and nothing else.
- The listener binds `127.0.0.1` only, so nothing but your own Tor can connect
  to it. Binding a real interface would accept direct connections and give the
  address away.
- IP endpoints sent by a peer are **discarded on arrival**, not deprioritised —
  an old build or a hostile peer cannot get you to dial one.
- Nothing is recorded about where an inbound peer came from.
- Tor failing to start is fatal. Falling back to a direct connection would
  publish exactly the address this design exists to keep private.

`test/tor.js` asserts all of these, plus the exact bytes of the SOCKS5 handshake
— most importantly that the destination leaves as a domain name, since an IP
there would mean this machine was resolving .onion addresses locally and leaking
who it's contacting.

## Security

- Identity is an Ed25519 key pair; your Mesh ID is a hash of the public key.
- Contact cards are signed. An altered card is rejected.
- Every connection runs a nonce challenge in both directions, so possessing
  someone's public card doesn't let you impersonate them.
- The channel key comes from X25519 ECDH between the two peers; every frame
  after the handshake is AES-256-GCM encrypted.
- `identity.json` holds your private keys. Anyone with that file is you.

## Tests

```
npm test
```

No install needed beyond `npm install` — the engine and its tests use only Node
built-ins. `test/crypto-and-transport.js` covers identity derivation, signature
forgery, tampered payloads, contact-card validation and a full two-peer
handshake. `test/tor.js` covers the SOCKS5 client, the control-port parser, and
every privacy invariant above.

These run without Tor and prove the mechanics. Whether a circuit reaches a
particular friend is something only two machines can establish.

## Layout

```
electron/main.js       app lifecycle, IPC, engine ownership
electron/preload.js    the only bridge to the UI
src/core/crypto.js     signing, key agreement, sealed frames
src/core/identity.js   key generation, Mesh ID derivation
src/core/card.js       signed contact codes
src/core/tor.js        tor process, onion service, SOCKS5 dialer
src/core/transport.js  framing, handshake, encrypted channel
src/core/roster.js     the engine: friends, links, messages
src/core/store.js      identity, friends and history on disk
scripts/get-tor.js     fetches and verifies Tor at install time
ui/                    the CRT terminal
```

## Licence

MIT.
