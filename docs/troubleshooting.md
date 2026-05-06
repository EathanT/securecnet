# Troubleshooting

## Build problems

### CMake cannot find libsodium

Set one or more of:

- `SECURECNET_LIBSODIUM_ROOT`
- `SODIUM_INCLUDE_DIR`
- `SODIUM_LIBRARY`

On Windows, a vcpkg toolchain file is often the easiest route.

### Warnings now fail the build

The repo intentionally builds project-owned targets with warnings-as-errors. Fix the warning in your code or temporarily configure with `-DSECURECNET_WARNINGS_AS_ERRORS=OFF` while iterating locally.

## Runtime problems

### Handshake never completes

Check:

- client/server protocol versions match
- firewall rules permit UDP traffic on the chosen port
- per-IP handshake rate limits are not being triggered in tests
- retry or resumption tokens are not stale
- your event loop is actually calling `tick()` often enough

### Packets close with authentication or protocol errors

Common causes:

- wrong session keys after a partial/manual handshake implementation
- accidental packet corruption in custom tooling
- old packets replayed after reconnect
- application code trying to use reserved `Control` channel messages directly

### Reliable sends return queue/backpressure errors

The per-peer packet queue, reliable queue, or send budget may be saturated. Slow the producer down, increase quotas in config, or shorten lifetimes for stale reliable messages.

### Large messages fail

Check these limits:

- `fragmentation.enabled`
- `fragmentation.max_reassembled_message_bytes`
- `fragmentation.max_fragments_per_message`
- `fragmentation.max_total_reassembly_memory_per_peer`
- server-wide `abuse.max_total_reassembly_memory_server`

### Session reconnect behavior seems odd

The server may replace an existing session from the same endpoint when a new handshake arrives. This is deliberate to keep reconnects deterministic.

## Debugging aids in the repo

- `TransportStats` exposes handshake, crypto, reliability, fragmentation, queue, and runtime counters.
- Logging callbacks let you observe state changes and failures.
- Packet debug hooks can dump parsed packets behind a debug flag.
- The smoke test and examples give you known-good local client/server flows.

