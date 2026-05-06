# Reliability model

securecnet keeps reliability at the message level rather than emulating a byte-stream transport.

## Delivery modes

### Unreliable

- Best-effort delivery.
- No acknowledgement or retransmission.
- Best for transient telemetry or state snapshots.

### Reliable unordered

- Every message receives a reliable message ID.
- Messages remain pending until acknowledged or expired.
- Delivery order is not guaranteed.

### Reliable ordered

- Uses both a reliable message ID and an ordered sequence number.
- Retransmitted until acknowledged or expired.
- Delivery is released to the application only in-order.
- Later packets can buffer behind a gap, but only within a bounded ordered receive window.

### Sequenced unreliable

- Carries a monotonically increasing sequence number.
- Older or duplicate sequences are dropped.
- Only the newest sequence is accepted.

## RTT/RTO behavior

The reliable subsystem tracks:

- latest RTT sample
- smoothed RTT
- RTT variance
- current retransmission timeout
- retransmit events
- loss events
- estimated loss per mille

The retransmission timeout starts from configuration, is updated from first-send ACK timing, and backs off exponentially when a message times out in-flight.

## Inflight and queue limits

The reliable session enforces:

- max pending reliable messages
- max pending reliable bytes
- max inflight reliable messages
- ordered receive window size

These limits stop one peer from growing memory without bound.

## Priorities and partial reliability

Every send has:

- `channel`
- `priority`
- `lifetime_ms`

Priority affects queue ordering. `lifetime_ms` allows partial reliability: once a message ages past its deadline, it expires out of the reliable queue instead of retransmitting forever.

## Acknowledgements

Reliable acknowledgements are explicit control-channel frames. The ack payload identifies both the reliable channel and the reliable message ID being acknowledged.

## Backpressure behavior

When send budgets, reliable queues, or pending packet queues fill up, the library returns queue/backpressure-style errors rather than silently discarding state. Applications should treat these as signals to slow down or shed work.

