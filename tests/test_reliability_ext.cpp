#include "securecnet/reliability.hpp"

#include <cstdio>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_reliability_ext() {
    int fails = 0;

    ReliabilityConfig cfg{};
    cfg.min_rto_ms = 50;
    cfg.max_rto_ms = 400;
    cfg.max_inflight_messages = 2;
    cfg.max_pending_messages = 8;
    cfg.max_pending_bytes = 4096;

    ReliableSession session{};
    session.configure(cfg);

    PendingReliableMessage a{};
    PendingReliableMessage b{};
    PendingReliableMessage c{};
    auto rc = session.enqueue(1, "aaa", 3, SendPriority::Normal, 0, 0, a);
    fails += expect(rc.ok(), "reliability_ext: enqueue a failed");
    rc = session.enqueue(2, "bbb", 3, SendPriority::Normal, 0, 0, b);
    fails += expect(rc.ok(), "reliability_ext: enqueue b failed");
    rc = session.enqueue(3, "ccc", 3, SendPriority::Low, 0, 0, c);
    fails += expect(rc.ok(), "reliability_ext: enqueue c failed");

    int send_calls = 0;
    rc = session.resend_due(1, [&](PendingReliableMessage&) {
        ++send_calls;
        return Result::success();
    });
    fails += expect(rc.ok(), "reliability_ext: initial resend_due failed");
    fails += expect(send_calls == 2, "reliability_ext: inflight limit should cap first send pass");
    fails += expect(session.inflight_count() == 2, "reliability_ext: inflight count mismatch after first send pass");

    auto ack = session.acknowledge(a.message_id, 61);
    fails += expect(ack.removed, "reliability_ext: ack for first packet should remove pending entry");
    fails += expect(ack.rtt_sample_valid && ack.rtt_sample_ms == 60,
                    "reliability_ext: first ack should record RTT sample");
    fails += expect(session.smoothed_rtt_ms() > 0, "reliability_ext: smoothed RTT should update");

    send_calls = 0;
    rc = session.resend_due(62, [&](PendingReliableMessage&) {
        ++send_calls;
        return Result::success();
    });
    fails += expect(rc.ok(), "reliability_ext: second resend_due failed");
    fails += expect(send_calls == 1, "reliability_ext: freed inflight slot should send next pending packet");

    const U64 rto_before_loss = session.pending().front().rto_ms;
    send_calls = 0;
    rc = session.resend_due(200, [&](PendingReliableMessage&) {
        ++send_calls;
        return Result::success();
    });
    fails += expect(rc.ok(), "reliability_ext: loss resend_due failed");
    fails += expect(send_calls >= 1, "reliability_ext: overdue packet should retransmit");
    fails += expect(session.loss_events() >= 1, "reliability_ext: loss events should increase on retransmit timeout");
    fails += expect(session.retransmit_events() >= 1, "reliability_ext: retransmit events should increase on timeout");
    fails += expect(session.pending().front().rto_ms >= rto_before_loss,
                    "reliability_ext: retransmission timeout should back off after loss");

    ack = session.acknowledge(b.message_id, 250);
    fails += expect(ack.removed, "reliability_ext: ack for retransmitted packet should remove entry");
    fails += expect(ack.retransmitted, "reliability_ext: retransmitted packet should report retransmitted=true");
    fails += expect(session.loss_per_mille() > 0, "reliability_ext: loss estimate should be non-zero after timeout");

    PendingReliableMessage expiring{};
    rc = session.enqueue(4, "ddd", 3, SendPriority::High, 10, 1000, expiring);
    fails += expect(rc.ok(), "reliability_ext: enqueue expiring packet failed");
    const U32 expired = session.expire_old(1011);
    fails += expect(expired == 1, "reliability_ext: expire_old should remove expired packet");

    return fails;
}
