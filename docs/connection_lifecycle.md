# Connection lifecycle

## State machine

A client or server-side session is always in one of five states:

- `Idle`
- `Handshaking`
- `Established`
- `Closing`
- `Closed`

State transitions are reflected in stats/logging and are enforced during packet handling.

## Client flow

1. `connect()` validates configuration, clears prior session state, opens the UDP socket, and creates a fresh ephemeral keypair.
2. The client enters `Handshaking` and sends `ClientHello`.
3. If the server answers with `Retry`, the client caches the retry token and resends `ClientHello`.
4. On `ServerHello`, the client derives session keys, validates the transcript MAC, updates connection ID/session keys, and transitions to `Established`.
5. The client begins sending keepalives and encrypted packets.
6. `close()` queues an explicit close packet and transitions through `Closing` to `Closed` after the drain timeout.

## Server flow

1. The server receives a `ClientHello` and performs cheap pre-session checks first: version, parse validity, rate limits, bans, anti-amplification accounting, and retry/resumption validation.
2. If retry is required, it sends a stateless retry token and avoids allocating session state.
3. Once the handshake is accepted, the server allocates a real connection ID, derives session keys, initializes delivery/reassembly state, and sends `ServerHello`.
4. The peer session transitions to `Established` and can exchange encrypted traffic.
5. On timeouts, invalid packets, or explicit close, the server transitions the peer through `Closing`/`Closed` and eventually evicts the session.

## Timeouts

### Handshake timeout

If the handshake does not complete before `handshake_timeout_ms`, the side in `Handshaking` closes with `EstablishTimeout`.

### Idle timeout

An established connection that stops receiving authenticated traffic for `idle_timeout_ms` closes with `IdleTimeout`.

### Close drain

After sending a close frame, the endpoint stays in `Closing` for `close_drain_ms` so the peer has a chance to observe the close before state is discarded.

## Keepalives

Keepalives are authenticated encrypted packets. They refresh idle timers without requiring application data.

## Session resumption

If enabled, the server may include a resumption token in `ServerHello`. On a future connect, the client can present that token instead of starting with a retry token. If the token validates, the server can skip the retry round-trip and establish the new session more quickly.

Resumption tokens are still bound to validation rules and expiry; a stale or invalid token does not silently succeed.

## Session eviction

The server evicts stale sessions during housekeeping. It also replaces an existing session from the same endpoint when a new handshake arrives, which keeps reconnect behavior predictable.

