#include "securecnet/reliability.hpp"

#include <cstdio>
#include <cstring>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_reliability() {
    int fails = 0;

    {
        U8 buf[64]{};
        ByteWriter w{ buf, sizeof(buf) };
        const char payload[] = "hey";

        auto rc = write_reliable_payload(w, 42, payload, 3);
        fails += expect(rc.ok(), "write_reliable_payload failed");

        ByteReader r{ buf, w.off };
        ReliablePayloadView view{};
        rc = read_reliable_payload(r, view);
        fails += expect(rc.ok(), "read_reliable_payload failed");
        fails += expect(view.message_id == 42, "reliable message id mismatch");
        fails += expect(view.len == 3, "reliable payload len mismatch");
        fails += expect(std::memcmp(view.data, payload, 3) == 0, "reliable payload bytes mismatch");
    }

    {
        U8 buf[16]{};
        ByteWriter w{ buf, sizeof(buf) };
        auto rc = write_reliable_ack(w, 99);
        fails += expect(rc.ok(), "write_reliable_ack failed");

        ByteReader r{ buf, w.off };
        U64 ack_id = 0;
        rc = read_reliable_ack(r, ack_id);
        fails += expect(rc.ok(), "read_reliable_ack failed");
        fails += expect(ack_id == 99, "reliable ack id mismatch");
    }

    {
        ReliableReceiveWindow window{};
        fails += expect(window.accept(10), "first reliable id should be accepted");
        fails += expect(!window.accept(10), "duplicate reliable id should be rejected");
        fails += expect(window.accept(11), "newer reliable id should be accepted");
        fails += expect(window.accept(9), "older in-window reliable id should be accepted once");
        fails += expect(!window.accept(9), "older duplicate reliable id should be rejected");
        fails += expect(window.accept(100), "far newer reliable id should be accepted");
        fails += expect(!window.accept(20), "very old reliable id should be rejected");
    }

    {
        ReliableSession session{};
        PendingReliableMessage first{};
        PendingReliableMessage second{};

        auto rc = session.enqueue(7, "abc", 3, first);
        fails += expect(rc.ok(), "enqueue first reliable message failed");
        rc = session.enqueue(8, "de", 2, second);
        fails += expect(rc.ok(), "enqueue second reliable message failed");
        fails += expect(session.pending_count() == 2, "pending reliable count mismatch after enqueue");

        int send_calls = 0;
        rc = session.resend_due(100, 50, [&](PendingReliableMessage&) {
            ++send_calls;
            return Result::success();
            });
        fails += expect(rc.ok(), "resend_due initial pass failed");
        fails += expect(send_calls == 2, "all queued reliable messages should be due on first pass");

        send_calls = 0;
        rc = session.resend_due(120, 50, [&](PendingReliableMessage&) {
            ++send_calls;
            return Result::success();
            });
        fails += expect(rc.ok(), "resend_due short interval failed");
        fails += expect(send_calls == 0, "reliable messages should not resend before delay");

        send_calls = 0;
        rc = session.resend_due(200, 50, [&](PendingReliableMessage&) {
            ++send_calls;
            return Result::success();
            });
        fails += expect(rc.ok(), "resend_due delayed interval failed");
        fails += expect(send_calls == 2, "reliable messages should resend after delay");

        fails += expect(session.acknowledge(first.message_id), "acknowledge should remove first reliable message");
        fails += expect(session.pending_count() == 1, "pending reliable count mismatch after ack");
        fails += expect(!session.acknowledge(first.message_id), "acknowledge should fail for already-acked message");
    }

    return fails;
}
