# securecnet

securecnet is a secure, message-oriented UDP networking library with authenticated session setup, encrypted packets, replay protection, bounded fragmentation/reassembly, multiple delivery modes, adaptive congestion-aware pacing, abuse controls, route/request helpers, and a testable event-loop API with an optional async runner.

## What is in the library

- Real libsodium-backed crypto, ephemeral session key exchange, authenticated encryption, and replay defense.
- A stateful client/server handshake with stateless retry, explicit close reasons, idle/handshake timeouts, keepalives, and server-issued session resumption tokens.
- Delivery modes for unreliable, reliable unordered, reliable ordered, and sequenced unreliable traffic.
- Optional bounded fragmentation for larger application messages.
- RTT-driven retransmission timeout, retransmit backoff, inflight limits, send priorities, and message lifetime/partial reliability.
- Per-peer send budgets, optional adaptive congestion-control pacing, receive/reassembly quotas, anti-amplification rules, per-IP handshake rate limiting, and invalid-packet penalties.
- Expanded stats, pluggable logging callbacks, and packet debug hooks.
- Unit/integration/fuzz-style tests, async tests, examples, benchmarks, and CI configuration.
- Optional `IoContext::run_async()` support with thread-safe bounded `try_post`, `post`, `post_task`, `stop`, and `join`.
- Optional helper utilities for NAT candidate exchange and a simple ordered stream framing layer.
- Message routers for application type dispatch and a request/reply envelope for correlated application transactions.
- Ergonomic helpers such as `send_reliable_text`, `send_ordered_text`, lifecycle callbacks, typed text callbacks, config presets/builders, and `AsyncClient` / `AsyncServer` wrappers.

## Project layout

- `src/securecnet/` — library headers and implementation.
- `tests/` — unit and integration tests.
- `src/demo/` — a terminal 2D shooter transport demo that exercises channel choices, fragmentation, raw encrypted packets, async posting, and congestion stats.
- `examples/` — echo, chat, state-sync, large-message, async echo, and request/reply examples.
- `bench/` — microbenchmarks, async posting benchmark, router dispatch benchmark, and lightweight allocation profiling.
- `docs/` — protocol, lifecycle, reliability, fragmentation, security, troubleshooting, performance, async runtime, updated reference, and roadmap status docs.

## Build requirements

- CMake 3.21+
- A C++20 compiler
- libsodium headers and library

## Linux quick start

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DSECURECNET_BUILD_TESTS=ON \
  -DSECURECNET_BUILD_EXAMPLES=ON \
  -DSECURECNET_BUILD_BENCHMARKS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The build checks pkg-config, common system locations, an optional `SECURECNET_LIBSODIUM_ROOT`, and versioned runtime libraries such as `libsodium.so.23`. This repository no longer ships large libsodium binary SDK artifacts; use your OS package manager, vcpkg, Conan, or pass `SODIUM_INCLUDE_DIR` and `SODIUM_LIBRARY` explicitly.

## Visual Studio 2026 notes

The library builds cleanly with CMake-based Visual Studio workflows. The repository includes CMake presets for Windows debug/release layouts, but you still need an actual libsodium binary available on disk.

Two practical Windows setups are:

1. Install libsodium with vcpkg and configure with the vcpkg toolchain file.
2. Set `SECURECNET_LIBSODIUM_ROOT`, `SODIUM_INCLUDE_DIR`, and/or `SODIUM_LIBRARY` to a local libsodium SDK.

Typical preset workflow:

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug-tests
```

If you use a custom libsodium location, set `SODIUM_INCLUDE_DIR` and `SODIUM_LIBRARY` in your local CMake configuration.

## Important CMake options

- `SECURECNET_BUILD_TESTS` — build test targets.
- `SECURECNET_BUILD_DEMO` — build the smoke-test demo.
- `SECURECNET_BUILD_EXAMPLES` — build example programs.
- `SECURECNET_BUILD_BENCHMARKS` — build benchmark executables.
- `SECURECNET_BUILD_DOC_SNIPPETS` — compile documentation snippets so examples stay API-accurate.
- `SECURECNET_BUILD_SHARED` — build `securecnet` as a shared library instead of a static library.
- `SECURECNET_WARNINGS_AS_ERRORS` — apply strict warnings to project-owned targets.
- `SECURECNET_ENABLE_SANITIZERS` — enable ASan/UBSan on supported toolchains.

## Threading and async model

securecnet is intentionally **event-loop oriented**. A `Client` or `Server` still has one owner thread, and callbacks still run on that owner thread. The upgrade adds an optional `IoContext::run_async()` helper so the owner loop can run on a dedicated worker thread.

- Use `IoContext::post`, bounded `IoContext::try_post`, or `IoContext::post_task` to call transport APIs from other application threads.
- Use `IoContext::stop` and `IoContext::join` before destroying registered services.
- `Client` and `Server` are not internally synchronized general-purpose shared objects; the async boundary is the context queue.
- `examples/async_echo_example.cpp` demonstrates the owner-loop pattern. `AsyncClient` and `AsyncServer` provide a higher-level wrapper for the common case.

## Abstraction levels

securecnet now has three intended API levels:

1. **Direct transport**: `Client`, `Server`, `SendOptions`, channels, raw payloads, and low-level packet/debug hooks.
2. **Application helpers**: named send helpers, typed callbacks, `ClientRouter`, `ServerRouter`, binary/text codecs, broadcast helpers, peer context, and request/reply envelopes.
3. **Async/easy wrappers**: `IoContext`, `AsyncClient`, `AsyncServer`, and `LocalSession` for owner-loop lifecycle management.

## Streamlined send API

For common sends, prefer the named helpers over hand-built options:

```cpp
client.send_unreliable_text(1, "telemetry");
client.send_latest_text(2, "position snapshot");
client.send_reliable_text(3, "unordered event");
client.send_ordered_text(4, "ordered command");
```

Use `on_text(type, fn)` for typed text handlers and `on_connected` / `on_disconnected` for lifecycle events. For async use, `scn::AsyncClient` and `scn::AsyncServer` own the context and handle stop/join lifecycle.


## Routing and request/reply

For applications with more than a couple of message types, prefer a router over a manual `switch` in every `on_message` callback:

```cpp
scn::ServerRouter routes;
routes.on_text(1, [](scn::Server::Peer peer, std::string_view text) {
  return peer.send_ordered_text(1, text);
});
routes.attach(server);
```

`ClientRequestTable` and the request/reply helpers provide a small correlated transaction layer above securecnet messages. They use normal encrypted, reliable, ordered, and fragmented sends; they do not change the core packet protocol.

## Running the programs

### 2D shooter transport demo

```bash
./build/src/demo/net_smoketest --server 27015
./build/src/demo/net_smoketest --client 127.0.0.1 27015 --name ace --ticks 80 --interval-ms 50
```

The demo is intentionally a transport showcase rather than a graphical game. It uses sequenced unreliable messages for latest-wins input and world snapshots, reliable unordered messages for shots and hit markers, reliable ordered messages for join/chat/kill-feed flow, reliable ordered fragmentation for a large arena blob, raw encrypted packets for telemetry/welcome pings, NAT/stream helper serialization, async `post_task` on the client, and adaptive congestion-control stats.

### Examples

```bash
./build/examples/secure_echo_example --server 27015
./build/examples/secure_echo_example --client 127.0.0.1 27015 hello

./build/examples/secure_chat_example --server 27015
./build/examples/secure_chat_example --client 127.0.0.1 27015

./build/examples/state_sync_example --server 27015
./build/examples/state_sync_example --client 127.0.0.1 27015

./build/examples/large_message_example --server 27015
./build/examples/large_message_example --client 127.0.0.1 27015 4096

./build/examples/async_echo_example

./build/examples/request_reply_example --server 27015
./build/examples/request_reply_example --client 127.0.0.1 27015 player-profile
```

### Benchmarks

```bash
./build/bench/bench_packet_encode_decode
./build/bench/bench_reliable_loss
./build/bench/bench_fragmented_transfer
./build/bench/bench_allocation_profile
./build/bench/bench_async_io_context
./build/bench/bench_router_dispatch
```

## Documentation index

- `docs/protocol_overview.md`
- `docs/packet_format.md`
- `docs/connection_lifecycle.md`
- `docs/reliability_model.md`
- `docs/fragmentation_reassembly.md`
- `docs/security_model.md`
- `docs/troubleshooting.md`
- `docs/performance.md`
- `docs/congestion_control.md`
- `docs/async_runtime.md`
- `docs/api_ergonomics.md`
- `docs/routing_request_reply.md`
- `docs/snippets/`
- `docs/securecnet_feature_reference_updated.md` / `.pdf`
- `docs/roadmap_status.md`
- `CHANGELOG.md`

