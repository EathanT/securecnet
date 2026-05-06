#include "securecnet/client.hpp"
#include "securecnet/server.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using namespace scn;

namespace {
constexpr U8 kClientTextType = 1;
constexpr U8 kServerTextType = 200;
}

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

int test_client_server() {
    int fails = 0;

    Server srv;
    auto rc = srv.listen(0);
    if (!rc.ok()) {
        std::printf(" server.listen failed\n");
        return 1;
    }

    Endpoint server_local{};
    rc = srv.local_endpoint(server_local);
    if (!rc.ok()) {
        std::printf(" server.local_endpoint failed\n");
        return 1;
    }

    Client cli;
    rc = cli.connect(server_local);
    if (!rc.ok()) {
        std::printf(" client.connect failed\n");
        return 1;
    }

    const bool established = pump_until(srv, cli, 500, [&] {
        return cli.state() == ConnectionState::Established && srv.peer_count() == 1;
    });
    fails += expect(established, "client/server handshake never established");
    if (!established) {
        return fails;
    }

    const std::string request_text = "hello-net";
    const std::string expected_reply = "echo:" + request_text;

    bool server_got_text = false;
    bool client_got_echo = false;
    bool server_got_reliable = false;
    bool client_got_reliable = false;

    srv.on_message([&](Server::Peer peer, const MsgView& msg) {
        if (msg.channel == Channel::Unreliable && msg.type == kClientTextType && msg.text() == request_text) {
            server_got_text = true;
            (void)peer.send_text(kServerTextType, expected_reply);
        }
        if (msg.channel == Channel::Reliable && msg.type == kClientTextType && msg.text() == request_text) {
            server_got_reliable = true;
            const auto reply_bytes = std::span<const U8>(reinterpret_cast<const U8*>(expected_reply.data()), expected_reply.size());
            (void)peer.send(Channel::Reliable, kServerTextType, reply_bytes);
        }
    });

    cli.on_message([&](const MsgView& msg) {
        if (msg.channel == Channel::Unreliable && msg.type == kServerTextType && msg.text() == expected_reply) {
            client_got_echo = true;
        }
        if (msg.channel == Channel::Reliable && msg.type == kServerTextType && msg.text() == expected_reply) {
            client_got_reliable = true;
        }
    });

    rc = cli.send_text(kClientTextType, request_text);
    if (!rc.ok()) {
        std::printf(" cli.send_text failed\n");
        return 1;
    }

    const auto request_bytes = std::span<const U8>(reinterpret_cast<const U8*>(request_text.data()), request_text.size());
    rc = cli.send(Channel::Reliable, kClientTextType, request_bytes);
    if (!rc.ok()) {
        std::printf(" cli.send reliable failed\n");
        return 1;
    }

    const bool exchanged = pump_until(srv, cli, 750, [&] {
        return server_got_text && client_got_echo && server_got_reliable && client_got_reliable;
    });
    fails += expect(exchanged, "message exchange did not complete");

    (void)pump_until(srv, cli, 150, [&] { return false; });

    const auto& client_stats = cli.stats();
    const auto& server_stats = srv.stats();
    fails += expect(client_stats.sessions_established >= 1, "client stats should count established session");
    fails += expect(server_stats.sessions_established >= 1, "server stats should count established session");
    fails += expect(client_stats.keepalives_sent >= 1, "client should send authenticated keepalive");
    fails += expect(server_stats.keepalives_received >= 1, "server should receive authenticated keepalive");
    fails += expect(client_stats.packets_sent >= 3, "client stats should count sent packets");
    fails += expect(client_stats.packets_received >= 2, "client stats should count received packets");
    fails += expect(client_stats.message_frames_sent >= 2, "client stats should count sent message frames");
    fails += expect(client_stats.message_frames_received >= 2, "client stats should count received message frames");
    fails += expect(client_stats.reliable_message_enqueued >= 1, "client stats should count reliable enqueues");
    fails += expect(client_stats.reliable_messages_delivered >= 1, "client stats should count reliable deliveries");
    fails += expect(client_stats.reliable_acks_sent >= 1, "client stats should count reliable acks sent");
    fails += expect(client_stats.reliable_acks_received >= 1, "client stats should count reliable acks received");
    fails += expect(server_stats.packets_sent >= 2, "server stats should count sent packets");
    fails += expect(server_stats.packets_received >= 3, "server stats should count received packets");
    fails += expect(server_stats.message_frames_sent >= 2, "server stats should count sent message frames");
    fails += expect(server_stats.message_frames_received >= 2, "server stats should count received message frames");
    fails += expect(server_stats.reliable_message_enqueued >= 1, "server stats should count reliable enqueues");
    fails += expect(server_stats.reliable_messages_delivered >= 1, "server stats should count reliable deliveries");
    fails += expect(server_stats.reliable_acks_sent >= 1, "server stats should count reliable acks sent");
    fails += expect(server_stats.reliable_acks_received >= 1, "server stats should count reliable acks received");

    rc = cli.close(CloseReason::Normal);
    fails += expect(rc.ok(), "client close should succeed");
    (void)pump_until(srv, cli, 300, [&] { return cli.state() == ConnectionState::Closed || srv.peer_count() == 0; });

    cli.stop();
    srv.stop();
    return fails;
}
