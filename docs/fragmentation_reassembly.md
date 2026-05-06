# Fragmentation and reassembly

securecnet keeps the small-packet fast path intact. Fragmentation is only used when an application message exceeds the inline budget for its delivery mode.

## When fragmentation happens

Fragmentation is considered only when:

- the channel's inline budget is exceeded, and
- fragmentation is enabled in configuration, and
- the message still fits within the configured reassembled-message limit.

Handshake traffic is never fragmented.

## Safety rules

The reassembly system is intentionally bounded:

- max fragments per message
- max reassembled message bytes
- max concurrent reassemblies per peer
- max total reassembly memory per peer
- max total reassembly memory across the server
- reassembly timeout for incomplete sets

Duplicate fragments are dropped cleanly. Impossible fragment sets, count mismatches, or policy-violating sizes are rejected.

## Authentication ordering

Fragments are only reassembled after packet authentication/decryption succeeds. This avoids spending reassembly resources on unauthenticated ciphertext.

## Reliable vs unreliable fragmentation

securecnet retransmits at the **whole-message level** on reliable channels. The fragment payload still travels inside authenticated message packets, but reliability bookkeeping is attached to the enclosing reliable message flow rather than to a separate per-fragment retransmission protocol.

## Operational behavior

- Unfragmented sends stay on the fast path.
- Fragmentation is optional and configurable.
- Incomplete reassemblies age out automatically.
- Reassembly memory usage is visible in runtime stats.

## Stats

The transport stats include counters for:

- fragmented messages sent/received
- fragments sent/received
- duplicate fragments
- invalid fragment sets
- completed reassemblies
- expired reassemblies
- reassembly drops and memory rejections

## Tests in the repo

The test suite covers:

- duplicate fragments
- out-of-order fragments
- expiry/cleanup
- size/memory rejection
- integrated fragmented transport round-trips
- parser fuzz coverage for fragment payload decoding

