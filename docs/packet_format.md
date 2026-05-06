# Packet format

## Fixed packet header

All packets begin with this fixed 28-byte header:

| Field | Size | Notes |
| --- | ---: | --- |
| `magic` | 4 | Constant protocol magic (`SCN3`). |
| `version` | 2 | Protocol version, currently `3`. |
| `kind` | 1 | `Raw`, `Handshake`, `Message`, `Keepalive`, or `Close`. |
| `flags` | 1 | `PacketFlagEncrypted` when payload is AEAD-protected. |
| `conn_id` | 8 | Server-issued connection ID. Zero is only valid before a session exists. |
| `seq` | 8 | Packet sequence number for replay defense and nonce derivation. |
| `payload_len` | 4 | Bytes following the header. |

The header is also used as AEAD additional authenticated data for encrypted packets.

## Handshake payloads

### `ClientHello`

Wire order:

1. Handshake type byte
2. Client ephemeral public key (32 bytes)
3. Client nonce (16 bytes)
4. Retry-token-present flag
5. Optional retry token
6. Resumption-token-present flag
7. Optional resumption token

### `Retry`

Wire order:

1. Handshake type byte
2. Retry token issue time (8 bytes)
3. Retry token MAC (16 bytes)

### `ServerHello`

Wire order:

1. Handshake type byte
2. Server connection ID (8 bytes)
3. Server ephemeral public key (32 bytes)
4. Server nonce (16 bytes)
5. Transcript MAC (16 bytes)
6. Resumption-token-present flag
7. Optional resumption token

### Resumption token

A resumption token contains:

- issue time (`u64`)
- expiry time (`u64`)
- ticket ID (`u64`)
- MAC (16 bytes)

Invalid or expired tokens are rejected during parse/validation.

## Framed message payloads

A `Message` packet may carry one or more message frames. Each frame is:

| Field | Size |
| --- | ---: |
| channel | 1 |
| application/control type | 1 |
| payload length | 2 |
| payload bytes | `len` |

## Reliable envelopes

Reliable delivery wraps a message payload inside a reliable envelope:

| Field | Size |
| --- | ---: |
| reliable message ID | 8 |
| payload bytes | variable |

Reliable ordered delivery adds an ordered sequence before entering the reliable layer:

| Field | Size |
| --- | ---: |
| ordered sequence | 8 |
| payload bytes | variable |

Sequenced unreliable delivery uses:

| Field | Size |
| --- | ---: |
| sequenced sequence | 8 |
| payload bytes | variable |

Reliable acknowledgements are carried on the `Control` channel and include:

| Field | Size |
| --- | ---: |
| channel being acknowledged | 1 |
| reliable message ID | 8 |

## Fragment payloads

Fragmented messages use the reserved fragment control type. Each fragment payload contains:

| Field | Size | Notes |
| --- | ---: | --- |
| message ID | 8 | Whole-message identity. |
| delivery sequence | 8 | Ordered/sequenced context if applicable. |
| channel | 1 | Original channel. |
| type | 1 | Original application/control type. |
| fragment index | 2 | Zero-based. |
| fragment count | 2 | Total fragments in set. |
| original length | 2 | Whole message length. |
| fragment bytes | variable | Up to `MaxFragmentDataBytes`. |

## Close packets

Close packets contain a small close frame with a 16-bit reason code. Common reasons include normal close, idle timeout, protocol error, invalid packet, authentication failure, rate limiting, and backpressure.

## NAT helper payloads

`nat.hpp` defines helper payloads for rendezvous systems:

- `NatPeerHint` — serialized IP family, port, and address bytes.
- `NatPunchFrame` — token + timestamp for lightweight punch packets.

## Stream helper payloads

`stream.hpp` defines an ordered stream frame:

| Field | Size |
| --- | ---: |
| stream ID | 2 |
| flags | 1 |
| payload length | 2 |
| payload | variable |

The `FIN` flag marks the last frame in a logical stream message.

