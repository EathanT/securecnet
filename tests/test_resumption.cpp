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

int test_resumption() {
    int fails = 0;

    ServerConfig server_cfg{};
    server_cfg.enable_session_resumption = true;
    ClientConfig client_cfg{};
    client_cfg.enable_session_resumption = true;

    Server srv{ server_cfg };
    auto rc = srv.listen(0);
    if (!rc.ok()) {
        std::printf(" resumption: server.listen failed\n");
        return 1;
    }

    Endpoint server_local{};
    if (!srv.local_endpoint(server_local).ok()) {
        std::printf(" resumption: server.local_endpoint failed\n");
        return 1;
    }

    Client cli{ client_cfg };
    if (!cli.connect(server_local).ok()) {
        std::printf(" resumption: client.connect failed\n");
        return 1;
    }

    bool established = pump_until(srv, cli, 750, [&] {
        return cli.state() == ConnectionState::Established && srv.peer_count() == 1;
    });
    fails += expect(established, "resumption: first handshake never established");
    if (!established) {
        return fails;
    }

    const U64 retries_after_first = srv.stats().handshake_retries_sent;
    fails += expect(retries_after_first >= 1, "resumption: first handshake should use retry before token issuance");

    rc = cli.close(CloseReason::Normal);
    fails += expect(rc.ok(), "resumption: first close should succeed");
    (void)pump_until(srv, cli, 500, [&] { return srv.peer_count() == 0; });
    cli.stop();
    (void)pump_until(srv, cli, 300, [&] { return srv.peer_count() == 0; });

    const U64 retries_before_second = srv.stats().handshake_retries_sent;
    rc = cli.connect(server_local);
    fails += expect(rc.ok(), "resumption: second connect should succeed");

    established = pump_until(srv, cli, 750, [&] {
        return cli.state() == ConnectionState::Established && srv.peer_count() == 1;
    });
    fails += expect(established, "resumption: second handshake never established");
    fails += expect(srv.stats().session_resumptions_attempted >= 1, "resumption: server should count resumption attempts");
    fails += expect(srv.stats().session_resumptions_accepted >= 1, "resumption: server should accept a valid resumption token");
    fails += expect(srv.stats().session_resumptions_rejected == 0, "resumption: server should not reject valid resumption token");
    fails += expect(cli.stats().session_resumptions_attempted >= 1, "resumption: client should count resumption attempts");
    fails += expect(cli.stats().session_resumptions_accepted >= 1, "resumption: client should count accepted resumption");
    fails += expect(srv.stats().handshake_retries_sent == retries_before_second,
                    "resumption: second handshake should not trigger another retry");

    (void)cli.close(CloseReason::Normal);
    (void)pump_until(srv, cli, 300, [&] { return srv.peer_count() == 0 || cli.state() == ConnectionState::Closed; });
    cli.stop();
    srv.stop();
    return fails;
}
