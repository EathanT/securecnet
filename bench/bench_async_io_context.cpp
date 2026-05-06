#include "bench_common.hpp"
#include "securecnet/io_context.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <thread>

using namespace scn;

int main() {
    constexpr std::size_t kTasks = 100000;

    IoContext ctx;
    auto rc = ctx.run_async();
    if (!rc.ok()) {
        std::printf("run_async failed: err=%u\n", static_cast<unsigned>(rc.code));
        return 1;
    }

    std::atomic<std::size_t> completed{ 0 };
    auto done = ctx.post_task([&] {
        for (std::size_t i = 0; i < kTasks; ++i) {
            ctx.post([&completed] { completed.fetch_add(1, std::memory_order_relaxed); });
        }
    });
    if (done.wait_for(std::chrono::seconds(2)) != std::future_status::ready) {
        std::printf("producer task timed out\n");
        ctx.stop();
        (void)ctx.join();
        return 1;
    }
    done.get();

    const long long total_ns = scn_bench::measure_ns([&] {
        while (completed.load(std::memory_order_relaxed) != kTasks) {
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
    });

    ctx.stop();
    rc = ctx.join();
    if (!rc.ok()) {
        std::printf("join failed: err=%u\n", static_cast<unsigned>(rc.code));
        return 1;
    }

    scn_bench::print_rate("async posted callbacks", total_ns, kTasks);
    return 0;
}
