#include "bench_common.hpp"

#include "securecnet/scn.hpp"

#include <array>
#include <cstdio>

using namespace scn;

int main() {
    constexpr int kMessages = 1'000'000;
    std::array<U8, 32> payload{};
    for (ST i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<U8>(i);
    }

    ClientRouter router;
    U64 checksum = 0;
    router.on(7, [&](const MsgView& msg) {
        checksum += msg.len;
    });

    MsgView msg{ Channel::Unreliable, 7, payload.data(), static_cast<U16>(payload.size()) };
    const auto elapsed_ns = scn_bench::measure_ns([&] {
        for (int i = 0; i < kMessages; ++i) {
            auto routed = router.dispatch(msg);
            if (!routed.ok() || !routed.handled) {
                std::printf("router dispatch failed\n");
                return;
            }
        }
    });

    scn_bench::print_rate("router dispatch", elapsed_ns, static_cast<std::size_t>(kMessages));
    std::printf("checksum=%llu\n", static_cast<unsigned long long>(checksum));
    return 0;
}
