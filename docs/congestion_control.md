# Adaptive congestion control

securecnet still uses bounded per-peer send queues and token-bucket pacing. The new congestion-control layer makes that pacing adaptive instead of purely fixed-rate when enabled in `ClientConfig::congestion` or `ServerConfig::congestion`.

This is deliberately practical game-transport congestion control, not a TCP/QUIC replacement. It adapts the application send budget from transport feedback that securecnet already has: reliable ACKs, retransmission timeout/loss events, and local queue or socket backpressure.

## Configuration

```cpp
scn::ClientConfig cfg = scn::ClientConfig::reliable_gameplay();
cfg.congestion.enabled = true;
cfg.congestion.min_rate_bytes_per_second = 64 * 1024;
cfg.congestion.initial_rate_bytes_per_second = 128 * 1024;
cfg.congestion.max_rate_bytes_per_second = 384 * 1024;
```

`max_rate_bytes_per_second == 0` means “use `send_budget_bytes_per_second` as the ceiling.” `initial_rate_bytes_per_second == 0` starts at half of that ceiling, clamped by the configured minimum.

## Signals

Positive signal:

- A first-transmission reliable ACK increases the current pacing rate additively.
- RTT samples from those ACKs update the reported congestion window estimate.

Negative signals:

- Reliable retransmission timeout/loss events apply multiplicative decrease.
- Local queue pressure or nonblocking socket `WouldBlock` applies a softer backoff.

The pacing bucket refills from the adaptive rate and is capped from the adaptive bucket/window estimate, so a peer that starts losing packets or building local pressure stops being fed at the old fixed rate.

## Stats

`TransportStats` now exposes:

```cpp
congestion_current_rate_bytes_per_second
congestion_current_window_bytes
congestion_ack_events
congestion_loss_events
congestion_backpressure_events
```

Client stats describe that one session. Server stats aggregate currently tracked peer sessions.

## Interaction with channels

The controller is transport-level. It does not change channel semantics:

- `SequencedUnreliable` remains best-effort/latest-wins.
- `Reliable` still retransmits unordered messages.
- `ReliableOrdered` still releases payloads in order.
- Fragmentation remains bounded and post-authentication.
- Raw encrypted packets still bypass message framing.

Reliable traffic provides the clearest ACK/loss feedback, so games should keep at least small reliable control/events flowing if they want the adaptive pacing estimate to stay fresh. Pure latest-wins traffic will still be paced, but it has less feedback to learn from.

## Demo mapping

`src/demo/net_smoketest.cpp` is now a terminal 2D shooter transport demo:

- client input: `SequencedUnreliable`
- server world snapshots: `SequencedUnreliable`
- shots and hit markers: `Reliable`
- join, chat, rules stream, kill feed: `ReliableOrdered`
- arena blob: reliable ordered fragmentation/reassembly
- telemetry/welcome: encrypted raw packets
- client owner loop: `IoContext::run_async()` plus `post_task()`
- runtime printouts: congestion rate/window/ACK/loss/backpressure counters

Run it with:

```bash
./build/src/demo/net_smoketest --server 27015
./build/src/demo/net_smoketest --client 127.0.0.1 27015 --name ace --ticks 80 --interval-ms 50
```
