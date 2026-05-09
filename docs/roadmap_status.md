# Roadmap status

This file maps the implementation state of the repo to the roadmap buckets.

## Baseline work that was already present in the uploaded project

The uploaded codebase already had most of the P0 security/core protocol work in place:

- libsodium-backed crypto
- handshake, retry, AEAD, replay defense
- explicit connection states
- connection IDs, keepalive, idle/handshake timeout, close frames
- parser hardening and core security tests

## Work completed in the first implementation pass

### P1 — fragmentation, reliability, congestion, abuse resistance, API cleanup

Completed in code and tests:

- bounded fragmentation/reassembly with limits, timeout, duplicate handling, and stats
- reliable unordered, reliable ordered, and sequenced unreliable delivery modes
- RTT/RTO tracking, retransmit backoff, inflight limits, loss estimation
- send priority and message lifetime support
- per-peer send budgets and backpressure accounting
- per-IP handshake rate limiting, invalid-packet penalties, anti-amplification, queued-reliable quotas, reassembly quotas
- config validation through `ClientConfig` / `ServerConfig`
- clearer error categories and explicit close semantics

### P2 — telemetry, tests, CI, docs, cross-platform hygiene

Completed in repo assets:

- expanded `TransportStats`
- pluggable logging and packet debug hooks
- new unit/integration tests for config, protocol, fragmentation, channel behavior, MTU boundaries, abuse limits, soak behavior, resumption, NAT helpers, and stream framing
- fuzz-style parser coverage extended to resumption and fragment parsing
- warnings-as-errors for project-owned targets
- CMake options for tests/examples/benchmarks/warnings/sanitizers
- Windows/Linux CI workflow definitions
- protocol/lifecycle/reliability/fragmentation/security/troubleshooting/performance docs
- example programs for echo, chat, state sync, and large messages

### P3 — performance work and optional extras

Completed or added as optional layers:

- benchmarks for packet encode/decode, reliable loss behavior, and fragmented transfer
- lightweight allocation profiling benchmark for hot paths
- channel priorities
- partial reliability / message expiry
- ordered channels
- server-issued session resumption tokens
- NAT rendezvous helper payloads (`nat.hpp`)
- optional ordered stream framing helper (`stream.hpp`)




### Async/event-loop ergonomics

Completed in code, examples, benchmarks, and tests:

- `IoContext::run_async()` for a dedicated background event-loop thread.
- Thread-safe `post`, `post_task`, `stop`, `join`, `restart`, `running`, and `stopped` helpers.
- Condition-variable wakeups instead of unconditional polling sleeps when posted work arrives.
- Async echo example showing the safe owner-thread dispatch pattern.
- Async benchmark for posted callback throughput.
- Async integration test for client/server echo through an async context.

### Correctness and hardening

- `UdpSocket` is now explicitly move-only, preventing accidental double-close/socket-handle aliasing.
- CMake libsodium discovery supports pkg-config, an optional SDK root, common system locations, and versioned runtime library names.
- Message, close-frame, reliable-envelope, ACK, and fragment parsing now reject invalid enum values and reserved zero reliable IDs earlier.
- Fragment reassembly performs defensive validation before indexing or allocation-sensitive work.
- AEAD helpers reject null AAD pointers when a nonzero AAD length is supplied.
- Client and server send APIs reject null data with nonzero length before building spans.
- Encrypted packet sequence zero is rejected after authentication and before replay-window mutation.
- Stale unbuilt scratch files were removed from the library implementation directory.

### Test and documentation additions

- `tests/test_validation_hardening.cpp` covers the new validation and ownership checks.
- `tests/test_async.cpp` covers async runner lifecycle, `post_task`, and async client/server echo.
- `docs/async_runtime.md` documents the async model and lifetime boundary.
- `CHANGELOG_UPGRADE.md` summarizes the capstone upgrade and validation results.


## 0.3 professional usability and hygiene pass

Completed in this pass:

- Added `ClientRouter` and `ServerRouter` to replace repeated application-side message switches.
- Added request/reply envelope helpers and `ClientRequestTable` for correlated application transactions without changing the transport wire protocol.
- Added a request/reply example, router/request tests, router dispatch benchmark, and compiled documentation snippet.
- Bumped package version to `0.3.0`; wire protocol version remains `3`.
- Removed heavyweight vendored libsodium binary artifacts while keeping optional header-only convenience files and package manager metadata.
- Removed duplicate/legacy source files from the implementation tree and fixed the conflicted `.gitignore`.
- Added vcpkg, Conan, and GitHub Actions CI metadata.
