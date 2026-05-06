#include "securecnet/client.hpp"
#include "securecnet/server.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <thread>
#include <vector>

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

static std::vector<U8> make_payload(U16 value) {
    std::vector<U8> payload(32);
    for (U16 i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<U8>((value + i) & 0xFFu);
    }
    return payload;
}

int test_soak() {
    int fails = 0;

    Server srv;
    auto rc = srv.listen(0);
    if (!rc.ok()) {
        std::printf(" soak: server.listen failed\n");
        return 1;
    }

    Endpoint server_local{};
    if (!srv.local_endpoint(server_local).ok()) {
        std::printf(" soak: server.local_endpoint failed\n");
        return 1;
    }

    Client cli;
    if (!cli.connect(server_local).ok()) {
        std::printf(" soak: client.connect failed\n");
        return 1;
    }

    const bool established = pump_until(srv, cli, 500, [&] {
        return cli.state() == ConnectionState::Established && srv.peer_count() == 1;
    });
    fails += expect(established, "soak: handshake never established");
    if (!established) {
        return fails;
    }

    constexpr U8 kReliableType = 61;
    constexpr U8 kReliableEchoType = 161;
    constexpr int kMessageCount = 64;

    int server_received = 0;
    int client_received = 0;

    srv.on_message([&](Server::Peer peer, const MsgView& msg) {
        if (msg.channel != Channel::ReliableOrdered || msg.type != kReliableType) {
            return;
        }
        ++server_received;
        SendOptions options{};
        options.channel = Channel::ReliableOrdered;
        (void)peer.send(options, kReliableEchoType, msg.bytes());
    });

    cli.on_message([&](const MsgView& msg) {
        if (msg.channel == Channel::ReliableOrdered && msg.type == kReliableEchoType && msg.len == 32) {
            ++client_received;
        }
    });

    for (int i = 0; i < kMessageCount; ++i) {
        const auto payload = make_payload(static_cast<U16>(i));
        rc = cli.send(Channel::ReliableOrdered, kReliableType,
                      std::span<const U8>(payload.data(), payload.size()));
        fails += expect(rc.ok(), "soak: reliable ordered send failed");
    }

    const bool completed = pump_until(srv, cli, 1500, [&] {
        return server_received == kMessageCount && client_received == kMessageCount;
    });
    fails += expect(completed, "soak: not all reliable ordered messages completed round trip");
    fails += expect(cli.state() == ConnectionState::Established,
                    "soak: client should remain established throughout run");
    fails += expect(server_received == kMessageCount,
                    "soak: server did not receive the expected message count");
    fails += expect(client_received == kMessageCount,
                    "soak: client did not receive the expected echo count");

    (void)cli.close(CloseReason::Normal);
    (void)pump_until(srv, cli, 300, [&] { return srv.peer_count() == 0 || cli.state() == ConnectionState::Closed; });
    cli.stop();
    srv.stop();
    return fails;
}
