# Performance and measurement

Performance work in this repo is measurement-first.

## Included benchmarks

The `bench/` directory ships with:

- `bench_packet_encode_decode` — packet pack/parse throughput.
- `bench_reliable_loss` — synthetic reliable-send behavior under delayed acknowledgements.
- `bench_fragmented_transfer` — encode/reassemble throughput for fragmented transfers.
- `bench_allocation_profile` — lightweight allocation counting for packet, reliable, and fragmentation hot paths.
- `bench_async_io_context` — posted callback throughput for the async context queue.
- `bench_router_dispatch` — route-table dispatch overhead for application message routers.

## What to measure first

1. Packet encode/decode cost.
2. Reliable send behavior when acknowledgements are delayed.
3. Fragmented-message throughput.
4. Allocations per operation in the hot path.
5. Posted callback overhead if using `IoContext::run_async`.
6. Router dispatch overhead if your application uses large route tables.
7. Congestion-control pacing behavior under ACK, retransmission, and queue-pressure signals.

## Current tuning knobs

- send budgets per client/server
- optional adaptive congestion-control rate bounds and backoff gains
- reliable queue size and inflight limits
- retransmission timeout bounds
- ordered receive window size
- fragmentation caps and timeouts
- async queue wake-up behavior and callback batching at the application layer

## Copies and pooling

The code already keeps many hot-path operations bounded and span-based, but it still copies into bounded pending queues and encoded message buffers by design. The allocation benchmark is there to tell you whether additional pooling or buffer reuse is worth the complexity on your workload.

## Batching

The current transport uses straightforward send/receive loops. If profiling later shows syscall overhead dominates, batching can be added with measurements to justify it. The message parser already accepts multiple frames in one message packet, so future batching can be added without changing the basic frame grammar.

## Rule of thumb

Do not optimize random paths because they look suspicious. Run the benchmarks first, then change the path that actually shows up in the numbers.

