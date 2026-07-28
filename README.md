# MeshChat

[![ci](https://github.com/VijayarajParamasivam/MeshChat/actions/workflows/ci.yml/badge.svg)](https://github.com/VijayarajParamasivam/MeshChat/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Peer-to-peer chat with no servers. Not "decentralised" in the sense of many
servers — there is no server. Your machine opens a TCP connection to your
friend's machine and the messages go down that wire and nowhere else.

No signalling server, no STUN, no TURN, no relay, no bootstrap node, no
directory, no account system. One dependency: Electron.

```
npm install
npm start
```

## Why this is hard on IPv4, and why IPv6 fixes it

On IPv4 your computer has **no address on the internet at all**. There are only
about 4.3 billion IPv4 addresses for far more devices, so your ISP shares one
address across many customers. A packet addressed "to you" has nowhere to be
delivered, because in IPv4 terms there is no "you". That's NAT, and it isn't a
permissions problem or something software can route around — the address genuinely
doesn't exist. It's the whole reason chat apps normally need a middleman: the
server isn't there to carry your words, it's there to be a fixed point both sides
can find.

**IPv6 removes the premise.** Addresses are 128 bits, so there are enough for every
device many times over, and most modern ISPs (in India, Jio and Airtel) hand your
laptop its own globally routable address. No sharing, no translation, no NAT. A
packet sent to that address reaches your machine the same way a packet to Google's
address reaches Google, and your friend can open a TCP connection straight to it.

So MeshChat tries, in order:

1. **IPv6 direct** — the real answer. Nothing to negotiate, nothing in the middle.
2. **IPv4 via your own router** — UPnP and NAT-PMP exist so a program on your
   network can ask for a port forward and ask what the public IP is. Your router
   is your hardware, so no third party is involved, and since the router reports
   the IP itself, no STUN server is needed either.
3. **Same-WiFi** — always works, zero configuration.

On startup you'll see which one you got:

```
> portal   public IPv6 — 2409:40f4:214d:8b5e:a992:523f:9051:2ee7
  no NAT between you and the internet. this is a genuinely direct path.
```

### The firewall is a different problem

Once you have IPv6, the only thing left blocking you is the firewall — and that's
a fundamentally different kind of obstacle. NAT was an *impossibility*: no address
to send to. A firewall is a *policy*: the packets can be delivered, something is
just choosing to drop them. Windows blocks unsolicited inbound by default, hardest
of all on the "Public" profile that most WiFi gets classified as.

Run `/firewall` and accept the prompt. That's the whole fix — for *your* firewall.
Somebody else's is another matter.

### When neither of you can be dialled

Windows you control. Your ISP's firewall, or a mobile carrier's, you don't — and
mobile networks drop unsolicited inbound as a matter of policy. Two people in
that position both look permanently offline to each other, and no amount of
retrying changes it.

The reason is narrower than it first appears. A stateful firewall doesn't block
inbound packets, it blocks packets belonging to no conversation, and the
conversation is keyed on the *whole* tuple — both addresses and both ports. Dial
out and your OS picks a random source port, so you open a pinhole for traffic
coming back to that port, while your friend is knocking on your listening port.
Both of you punch holes, both holes are in the wrong place.

Make the two flows mirror each other and the problem disappears:

```
you  -> them:   [you]:47777  -> [them]:47777
them -> you:    [them]:47777 -> [you]:47777
```

Now each side's outbound flow is exactly the inbound flow the other one needs,
and each firewall sees an arriving packet as the reply to something its own user
already sent. Nothing in the middle has to cooperate. The only thing both ends
must agree on is the port, which is already in the contact card — so there is
still no server, no STUN, and no third party of any kind.

The catch is timing: a pinhole lives for tens of seconds, so both sides have to
be sending at roughly the same moment. With nothing to coordinate through, they
align on the wall clock instead, firing on a fixed 30-second boundary since the
epoch. Clocks within a few seconds of each other land in the same window.

Run `/punch <friend>` on both machines. It also happens automatically whenever an
ordinary dial fails and the friend has an IPv6 address.

This is UDP, not TCP. The technique works for both, but carriers treat a bare SYN
from an unexpected direction far more harshly than a datagram. The cost is that
UDP guarantees no ordering or delivery, so `src/core/punch.js` adds sequence
numbers, cumulative acks and retransmission underneath — and presents the result
as something shaped like a socket, so the handshake and encryption above it never
learn they moved off TCP.

**It is not guaranteed.** Some carriers refuse even reciprocal flows. Test yours
before relying on it, on both machines at once:

```
npm run punch-test -- <their-ipv6-address>
```

That uses only the punch layer — no keys, no friend list — so if it fails, the
network refused the technique rather than something breaking higher up. If it
does fail, one end genuinely needs a connection that accepts inbound: wired
broadband with an IPv6 pinhole open for TCP and UDP 47777. Only one, though —
once either side is reachable, the other can always dial out to it.

## Using it

First launch asks for a handle. That's just a label — your real identity is an
Ed25519 key pair generated on this machine, and your Mesh ID is a hash of its
public half, so nobody can claim your ID without your private key.

To add a friend, run `/card`, send the code to them however you like (WhatsApp,
email, paper), and they run `/add <code>`. **Only one of you needs to do it** —
when they dial in and prove who they are, you accept them automatically, since
the only way they could know your address is that you gave them the card.

```
/help              all commands
/card              print your contact code
/copy              copy it to the clipboard
/add <code>        add a friend
/friends           who you know and who's online
/chat <who>        open a conversation
/nearby            other MeshChat instances on this WiFi
/net               connection diagnostics
/try <who>         force a connection attempt and show why it failed
/punch <who>       hole-punch when neither side can be dialled
/firewall          allow inbound connections (asks for admin)
/export            back up your identity
```

Anything that isn't a slash command is sent to whoever you're chatting with.
Messages show `[~]` queued, `[>]` sent, `[ok]` delivered.

### Two instances on one machine

```
npm start          you
npm run start:b    a second, completely separate identity
```

They get separate data directories and separate keys, and the TCP port
auto-increments. Useful for trying it out before you have anyone to talk to.

## "We added each other but both show offline"

Run `/try <friend>`. It forces a connection attempt and prints every address it
tried and exactly how each one failed, which narrows the cause immediately:

- **nothing is listening** — you reached their machine, but MeshChat isn't
  running or is on another port.
- **no reply** — packets are being dropped. A firewall, their router, or the
  ISP. Both of you should run `/firewall`; if that doesn't do it and you both
  have IPv6, try `/punch`.
- **no route from here** — your machine has no path to that kind of address,
  which almost always means they published an IPv6 address and you have no IPv6.

Then run `/ipv6` on both machines. It reports whether you have an
internet-routable address and, if not, which of the four usual causes applies.

### `ipconfig` shows IPv6 but MeshChat says none

This is the most common confusion, and MeshChat is right.

Every Windows machine always has a **link-local** address starting `fe80::`,
whether or not the network carries IPv6 at all. It's generated by the network
card itself and never travels past your own cable. `ipconfig` labels it
"Link-local IPv6 Address", and it looks exactly like having IPv6.

A real internet address appears on a separate "IPv6 Address" line and **starts
with 2 or 3** (like `2409:...`). An address starting `fd` is also private — the
IPv6 equivalent of `192.168.x.x` — and equally unreachable.

`/net` now lists these explicitly and says why they don't count.

**Both sides need real IPv6 for the direct path.** IPv4-only machines physically
cannot send packets to an IPv6 address, so if one of you lacks it there is no
shared route at all.

Tethering from a Jio phone is the fastest way to *get* an address — Indian mobile
networks are IPv6-first — but be clear about what it buys you. A hotspot hands
out a genuine global address that nothing can dial in to, because the carrier
drops unsolicited inbound. It looks like working IPv6 and behaves like a wall.
That combination is exactly what `/punch` exists for, and the honest test of
whether your carrier allows it is `npm run punch-test`.

## Reality check

**Both sides need IPv6 for the direct path.** That's the one real condition. Most
Indian mobile and broadband connections have it, but a friend on an IPv4-only
network can't be reached that way — that pair falls back to UPnP, and failing
that, to same-WiFi.

**IPv4 on the network this was built on is a dead end** (`10.96.141.x`, typical of
campus, office and hotspot networks): the router refuses UPnP. That used to mean
no internet chat at all. It doesn't any more, because the same machine has a
public IPv6 address and never needed the router's permission in the first place.

**Carrier-grade NAT** makes IPv4 inbound impossible no matter what you configure,
because the ISP is NATing you too. `/net` says so plainly. It has no bearing on
IPv6, which is usually the same ISPs' answer to running out of IPv4.

**Windows Firewall blocks inbound by default.** Run `/firewall` once. Without it,
a perfectly good IPv6 path still gets you nothing.

**IPv6 addresses rotate.** Windows uses a stable address plus a rotating privacy
one, and prefixes change when you reconnect. Cards list every address, and
connected peers are told automatically whenever yours change. If you're both
offline long enough for both to move, re-share a card.

**No offline delivery.** With no server there's nowhere to park a message for
someone who's away. Messages you send while a friend is offline are queued on
*your* disk and flushed automatically when they reappear.

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

No install needed — the engine and its tests use only Node built-ins, so this
runs on a bare checkout. `test/crypto-and-transport.js` covers identity
derivation, signature forgery, tampered payloads, contact-card validation and a
real two-peer handshake over a socket. `test/ipv6.js` dials the machine's own
global IPv6 address to prove the direct path, and skips where no IPv6 exists.
`test/punch.js` covers window alignment, the two-way punch, and the reliability
layer — including reordering and duplicates, which UDP produces and TCP never
does — then runs a full identity handshake over a punched session to confirm the
crypto above can't tell the transport changed underneath it.

Those run on loopback, so they prove the mechanics rather than that your carrier
permits them. `npm run punch-test -- <address>`, run on both machines at once, is
the test for that.

## Layout

```
electron/main.js       app lifecycle, IPC, engine ownership
electron/preload.js    the only bridge to the UI
src/core/crypto.js     signing, key agreement, sealed frames
src/core/identity.js   key generation, Mesh ID derivation
src/core/portal.js     IPv6 discovery, UPnP + NAT-PMP port mapping
src/core/punch.js      UDP hole punching and its reliability layer
src/core/firewall.js   Windows inbound allow rule
src/core/card.js       signed contact codes
src/core/transport.js  framing, handshake, TCP server and dialer
src/core/roster.js     friends, reconnect, message flow
src/core/lan.js        multicast discovery for same-network peers
src/core/store.js      identity, friends and history on disk
ui/                    the terminal
test/                  dependency-free test harnesses
```
