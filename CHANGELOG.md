# Changelog

## 0.3.0 - professional API and repository hygiene pass

### Added

- `ClientRouter` and `ServerRouter` for message-type dispatch with text, binary, fallback, and error handlers.
- Request/reply envelope helpers with `RequestReplyFrame`, `ClientRequestTable`, response helpers, timeout expiry, and compiled documentation snippets.
- `request_reply_example` showing correlated request/response logic over the existing secure message transport.
- `bench_router_dispatch` to measure route-table dispatch overhead.
- Package metadata for vcpkg and Conan.
- GitHub Actions CI workflow that builds examples, benchmarks, documentation snippets, and tests.

### Improved

- `AsyncClient` send helpers now ensure the owned `IoContext` worker is running before queueing sends.
- The echo example now uses `ServerRouter`, `ClientRouter`, lifecycle callbacks, and named send helpers instead of manual message switches and state polling.
- Documentation now describes the three intended abstraction levels: direct transport, routers/request-reply, and async/easy wrappers.
- Package version bumped to `0.3.0`; wire protocol version remains unchanged.

### Removed or trimmed

- Removed large vendored libsodium binary SDK artifacts from the source tree.
- Kept only small libsodium public headers as a convenience for environments with a runtime library but no development package.
- Removed duplicate `include/securecnet/crypto.cpp` implementation copy.
- Removed stale legacy `src/securecnet/lib/test_security.cpp` source that was not part of the build.
- Replaced the conflicted, oversized `.gitignore` with a focused C++/CMake ignore file.
