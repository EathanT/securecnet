#include "bench_common.hpp"
#include "securecnet/reliability.hpp"

#include <array>

using namespace scn;

int main() {
    constexpr std::size_t kMessages = 4096;
    constexpr std::size_t kTicks = 4096;

    ReliabilityConfig cfg{};
    cfg.max_pending_messages = static_cast<U32>(kMessages + 32);
    cfg.max_pending_bytes = 512 * 1024;
    cfg.max_inflight_messages = 32;
    cfg.min_rto_ms = 40;
    cfg.initial_rto_ms = 100;
    cfg.max_rto_ms = 800;

    ReliableSession session{};
    session.configure(cfg);

    std::array<U8, 48> payload{};
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<U8>((i * 7u) & 0xFFu);
    }

    for (std::size_t i = 0; i < kMessages; ++i) {
        PendingReliableMessage pending{};
        auto rc = session.enqueue(1,
                                  payload.data(),
                                  static_cast<U16>(payload.size()),
                                  SendPriority::Normal,
                                  0,
                                  1,
                                  pending);
        if (!rc.ok()) {
            std::printf("enqueue failed: err=%u\n", static_cast<unsigned>(rc.code));
            return 1;
        }
    }

    U64 now_ms = 1;
    const long long total_ns = scn_bench::measure_ns([&]() {
        for (std::size_t tick = 0; tick < kTicks; ++tick) {
            auto rc = session.resend_due(now_ms, [&](PendingReliableMessage&) {
                return Result::success();
            });
            if (!rc.ok()) {
                std::printf("resend_due failed: err=%u\n", static_cast<unsigned>(rc.code));
                std::abort();
            }

            const auto pending_snapshot = session.pending();
            for (const auto& message : pending_snapshot) {
                if (!message.inflight) {
                    continue;
                }
                const bool delayed = (message.message_id % 5u) == 0u;
                const U64 ack_delay = delayed ? 180 : 60;
                if (now_ms < (message.first_send_ms + ack_delay)) {
                    continue;
                }
                (void)session.acknowledge(message.message_id, now_ms);
            }
            now_ms += 20;
        }
    });

    scn_bench::print_rate("reliable synthetic loss", total_ns, kTicks);
    std::printf("remaining=%zu retransmits=%llu losses=%llu srtt=%llu rto=%llu loss_per_mille=%llu\n",
                session.pending_count(),
                static_cast<unsigned long long>(session.retransmit_events()),
                static_cast<unsigned long long>(session.loss_events()),
                static_cast<unsigned long long>(session.smoothed_rtt_ms()),
                static_cast<unsigned long long>(session.rto_ms()),
                static_cast<unsigned long long>(session.loss_per_mille()));
    return 0;
}
