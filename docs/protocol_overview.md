# Protocol overview

securecnet is a message-oriented UDP transport. It does not expose a TCP-like byte stream by default; the application sends messages on explicit channels and the library applies the delivery semantics for that channel.

## Packet kinds

Every wire packet begins with a fixed header and one of these packet kinds:

- `Raw` — encrypted opaque payloads without message framing.
- `Handshake` — cleartext handshake packets.
- `Message` — encrypted framed application/control messages.
- `Keepalive` — encrypted authenticated keepalive packets.
- `Close` — explicit close packets with reason codes.

## Channels

The message layer supports these channels:

- `Unreliable` — best-effort datagrams.
- `Reliable` — retransmitted until acknowledged, unordered delivery.
- `ReliableOrdered` — retransmitted and delivered in-order.
- `SequencedUnreliable` — best-effort, only the newest sequence is accepted.
- `Control` — reserved for internal acknowledgements and fragment control data.

## Connection states

Both peers move through explicit states:

1. `Idle`
2. `Handshaking`
3. `Established`
4. `Closing`
5. `Closed`

State-awareness is enforced throughout packet handling. Illegal packets for the current state are rejected and counted.

## Handshake summary

1. The client generates a fresh ephemeral keypair and a client nonce.
2. The client sends a `ClientHello`.
3. The server may answer with a stateless retry token before spending session state.
4. Once validated, the server creates its own ephemeral keypair, derives session keys, allocates a real connection ID, and returns `ServerHello`.
5. The client verifies the transcript MAC, derives matching session keys, and transitions to `Established`.
6. Both sides begin exchanging encrypted packets with replay protection.

If session resumption is enabled, the server may issue a resumption token in `ServerHello`, and future connects can skip the retry round-trip when the token is still valid.

## Reliability summary

Reliable channels use message-level acknowledgements and RTT-driven retransmission timers. Ordered delivery uses a receive buffer keyed by ordered sequence numbers. Sequenced delivery keeps only the newest sequence.

## Fragmentation summary

Messages larger than a channel's inline budget are optionally fragmented. Fragments are authenticated/decrypted before reassembly, and reassembly is bounded by per-message, per-peer, and server-wide memory quotas.

## Optional helper layers

The repo also includes:

- `nat.hpp` for NAT rendezvous hint serialization and punch-frame helpers.
- `stream.hpp` for an optional ordered stream framing layer on top of reliable ordered delivery.

