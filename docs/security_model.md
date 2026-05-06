# Security model

## Cryptographic primitives

securecnet uses libsodium for the security-critical path.

- Session key exchange uses libsodium `crypto_kx` APIs with fresh ephemeral keys per session.
- Packet encryption uses `crypto_aead_xchacha20poly1305_ietf_*`.
- Transcript/cookie/resumption MACs use keyed generic hashing.

## Session keys

Each session derives separate transmit and receive keys. Client and server derive complementary key directions from their ephemeral key exchange.

## Packet authentication

Encrypted packets authenticate the packet header as AEAD additional authenticated data. Header tampering therefore fails authentication, even though the header itself is not encrypted.

## Replay defense

Each encrypted packet carries a sequence number. The receiver tracks it with a replay window and rejects duplicates/too-old packets.

## Stateless retry

Before the server commits session state, it can issue a stateless retry token bound to the handshake context and endpoint. This reduces spoofed handshake abuse and helps preserve anti-amplification posture.

## Anti-amplification

Before a session is established, the server tracks how many bytes it has received from a source and limits how many bytes it will send back, subject to a small slack allowance.

## Session resumption

The server can issue a resumption token in `ServerHello`. A later connect can present that token to bypass the retry round-trip when valid. Invalid or expired tokens are rejected and counted.

## Abuse controls

The server also tracks:

- per-IP handshake rate limits
- invalid-packet penalty scores and temporary bans
- per-IP session caps
- queued reliable byte quotas
- reassembly memory quotas

## Parser hardening

The codebase rejects:

- unsupported protocol versions
- malformed headers
- truncated fields
- illegal state/packet combinations
- invalid fragment metadata
- invalid token flags/lengths

These failures are surfaced as explicit errors and stats rather than being ignored silently.

## Zeroization

Ephemeral/session key material is cleared when sessions are reset or fail, which limits how long sensitive material stays resident after a connection ends.

## What securecnet is and is not

securecnet provides authenticated, encrypted session transport over UDP. It is not a NAT traversal service, relay network, identity PKI, or access-control framework by itself. Applications still need their own authorization and trust model above the transport layer.

