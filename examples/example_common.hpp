#pragma once

#include "securecnet/scn.hpp"

#include <chrono>
#include <cstdio>
#include <functional>
#include <thread>
#include <vector>

namespace scn_examples {

    inline int print_result(const char* label, const scn::Result& rc) {
        std::printf("%s: err=%u msg=%.*s\n",
                    label,
                    static_cast<unsigned>(rc.code),
                    static_cast<int>(rc.msg.size()),
                    rc.msg.data() ? rc.msg.data() : "");
        return 1;
    }

    template <class Predicate>
    bool pump_until(scn::Client& cli, int timeout_ms, Predicate&& predicate) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            auto rc = cli.tick();
            if (!rc.ok()) {
                return false;
            }
            if (predicate()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return predicate();
    }

    template <class Predicate>
    bool pump_until(scn::Server& srv, int timeout_ms, Predicate&& predicate) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            auto rc = srv.tick();
            if (!rc.ok()) {
                return false;
            }
            if (predicate()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return predicate();
    }

    template <class Predicate>
    bool pump_until(scn::Server& srv, scn::Client& cli, int timeout_ms, Predicate&& predicate) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            auto src = srv.tick();
            auto crc = cli.tick();
            if (!src.ok() || !crc.ok()) {
                return false;
            }
            if (predicate()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return predicate();
    }

    inline std::vector<U8> make_pattern_payload(ST len, U8 seed) {
        std::vector<U8> payload(len);
        for (ST i = 0; i < len; ++i) {
            payload[i] = static_cast<U8>((static_cast<U32>(seed) + static_cast<U32>(i * 11u)) % 251u);
        }
        return payload;
    }

} // namespace scn_examples
