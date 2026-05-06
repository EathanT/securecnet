#include "securecnet/client.hpp"
#include "securecnet/server.hpp"

#include <chrono>
#include <cstdio>
#include <functional>
#include <thread>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

static bool pump_until(Server& srv, Client& cli, int timeout_ms, const std::function<bool()>& predicate) {
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

static bool pump_until(Server& srv, Client& first, Client& second, int timeout_ms, const std::function<bool()>& predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto src = srv.tick();
        auto first_rc = first.tick();
        auto second_rc = second.tick();
        if (!src.ok() || !first_rc.ok() || !second_rc.ok()) {
            return false;
        }
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

int test_abuse() {
    int fails = 0;

    ServerConfig server_cfg{};
    server_cfg.abuse.per_ip_handshake_rate_limit_per_second = 2;
    server_cfg.abuse.max_sessions_per_ip = 4;
    server_cfg.handshake_timeout_ms = 250;

    ClientConfig client_cfg{};
    client_cfg.handshake_timeout_ms = 250;

    Server srv{ server_cfg };
    auto rc = srv.listen(0);
    if (!rc.ok()) {
        std::printf(" abuse: server.listen failed\n");
        return 1;
    }

    Endpoint server_local{};
    if (!srv.local_endpoint(server_local).ok()) {
        std::printf(" abuse: server.local_endpoint failed\n");
        return 1;
    }

    Client first{ client_cfg };
    Client second{ client_cfg };
    if (!first.connect(server_local).ok()) {
        std::printf(" abuse: first.connect failed\n");
        return 1;
    }

    const bool first_established = pump_until(srv, first, 500, [&] {
        return first.state() == ConnectionState::Established;
    });
    fails += expect(first_established, "abuse: first client should establish before second connect");
    if (!first_established) {
        first.stop();
        second.stop();
        srv.stop();
        return fails;
    }

    if (!second.connect(server_local).ok()) {
        std::printf(" abuse: second.connect failed\n");
        return 1;
    }

    const bool observed = pump_until(srv, first, second, 1000, [&] {
        return first.state() == ConnectionState::Established && second.state() == ConnectionState::Closed;
    });
    fails += expect(observed, "abuse: expected one client to establish and one to time out under rate limiting");
    fails += expect(srv.stats().rate_limited_packets >= 1,
                    "abuse: server should record rate-limited handshake traffic");
    fails += expect(first.state() == ConnectionState::Established,
                    "abuse: first client should still establish successfully");
    fails += expect(second.close_reason() == CloseReason::EstablishTimeout,
                    "abuse: second client should close with establish timeout after dropped handshakes");

    (void)first.close(CloseReason::Normal);
    (void)pump_until(srv, first, second, 300, [&] { return srv.peer_count() == 0 || first.state() == ConnectionState::Closed; });
    first.stop();
    second.stop();
    srv.stop();
    return fails;
}
