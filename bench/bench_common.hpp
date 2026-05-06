#pragma once

#include <chrono>
#include <cstdio>

namespace scn_bench {

    template <class Fn>
    long long measure_ns(Fn&& fn) {
        const auto start = std::chrono::steady_clock::now();
        fn();
        const auto end = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    }

    inline void print_rate(const char* label, long long total_ns, std::size_t ops) {
        const double ns_per_op = (ops == 0) ? 0.0 : static_cast<double>(total_ns) / static_cast<double>(ops);
        const double ops_per_sec = (total_ns <= 0) ? 0.0 : (static_cast<double>(ops) * 1.0e9) / static_cast<double>(total_ns);
        std::printf("%-28s total=%lld ns  ns/op=%.2f  ops/s=%.2f\n", label, total_ns, ns_per_op, ops_per_sec);
    }

} // namespace scn_bench
