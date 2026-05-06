# securecnet

securecnet is a secure, message-oriented UDP networking library with authenticated session setup, encrypted packets, replay protection, bounded fragmentation/reassembly, multiple delivery modes, abuse controls, and a testable event-loop API with an optional async runner.

## What is in the library

- Real libsodium-backed crypto, ephemeral session key exchange, authenticated encryption, and replay defense.
- A stateful client/server handshake with stateless retry, explicit close reasons, idle/handshake timeouts, keepalives, and server-issued session resumption tokens.
- Delivery modes for unreliable, reliable unordered, reliable ordered, and sequenced unreliable traffic.
- Optional bounded fragmentation for larger application messages.
- RTT-driven retransmission timeout, retransmit backoff, inflight limits, send priorities, and message lifetime/partial reliability.
- Per-peer send budgets, receive/reassembly quotas, anti-amplification rules, per-IP handshake rate limiting, and invalid-packet penalties.
- Expanded stats, pluggable logging callbacks, and packet debug hooks.
- Unit/integration/fuzz-style tests, async tests, examples, benchmarks, and CI configuration.
- Optional `IoContext::run_async()` support with thread-safe `post`, `post_task`, `stop`, and `join`.
- Optional helper utilities for NAT candidate exchange and a simple ordered stream framing layer.

## Project layout

- `src/securecnet/` — library headers and implementation.
- `tests/` — unit and integration tests.
- `src/demo/` — a small transport smoke-test program.
- `examples/` — echo, chat, state-sync, large-message, and async echo examples.
- `bench/` — microbenchmarks, async posting benchmark, and lightweight allocation profiling.
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

The build now checks the bundled `external/libsodium` path, pkg-config, common system locations, and versioned runtime libraries such as `libsodium.so.23`. If CMake still cannot find libsodium automatically, pass `SODIUM_INCLUDE_DIR` and `SODIUM_LIBRARY` explicitly.

## Visual Studio 2026 notes

The library builds cleanly with CMake-based Visual Studio workflows. The repository includes CMake presets for Windows debug/release layouts, but you still need an actual libsodium binary available on disk.

Two practical Windows setups are:

1. Extract a libsodium SDK under `external/libsodium/` and let the presets find it.
2. Use vcpkg and configure with the vcpkg toolchain file.

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
- `SECURECNET_WARNINGS_AS_ERRORS` — apply strict warnings to project-owned targets.
- `SECURECNET_ENABLE_SANITIZERS` — enable ASan/UBSan on supported toolchains.

## Threading and async model

securecnet is intentionally **event-loop oriented**. A `Client` or `Server` still has one owner thread, and callbacks still run on that owner thread. The upgrade adds an optional `IoContext::run_async()` helper so the owner loop can run on a dedicated worker thread.

- Use `IoContext::post` or `IoContext::post_task` to call transport APIs from other application threads.
- Use `IoContext::stop` and `IoContext::join` before destroying registered services.
- `Client` and `Server` are not internally synchronized general-purpose shared objects; the async boundary is the context queue.
- `examples/async_echo_example.cpp` demonstrates the recommended pattern.

## Running the programs

### Smoke test

```bash
./build/src/demo/net_smoketest --server 27015
./build/src/demo/net_smoketest --client 127.0.0.1 27015 --message hello --reliable
```

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
```

### Benchmarks

```bash
./build/bench/bench_packet_encode_decode
./build/bench/bench_reliable_loss
./build/bench/bench_fragmented_transfer
./build/bench/bench_allocation_profile
./build/bench/bench_async_io_context
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
- `docs/async_runtime.md`
- `docs/securecnet_feature_reference_updated.md` / `.pdf`
- `docs/roadmap_status.md`

