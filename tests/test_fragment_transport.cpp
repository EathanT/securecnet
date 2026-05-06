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

static std::vector<U8> make_payload(ST len, U8 seed) {
    std::vector<U8> payload(len);
    for (ST i = 0; i < len; ++i) {
        payload[i] = static_cast<U8>((static_cast<U32>(seed) + static_cast<U32>(i * 13u)) % 251u);
    }
    return payload;
}

static bool bytes_match(const MsgView& msg, const std::vector<U8>& expected) {
    return msg.len == expected.size() && std::memcmp(msg.data, expected.data(), expected.size()) == 0;
}

int test_fragment_transport() {
    int fails = 0;

    Server srv;
    auto rc = srv.listen(0);
    if (!rc.ok()) {
        std::printf(" fragment transport: server.listen failed\n");
        return 1;
    }

    Endpoint server_local{};
    if (!srv.local_endpoint(server_local).ok()) {
        std::printf(" fragment transport: server.local_endpoint failed\n");
        return 1;
    }

    Client cli;
    if (!cli.connect(server_local).ok()) {
        std::printf(" fragment transport: client.connect failed\n");
        return 1;
    }

    const bool established = pump_until(srv, cli, 500, [&] {
        return cli.state() == ConnectionState::Established && srv.peer_count() == 1;
    });
    fails += expect(established, "fragment transport: client/server handshake never established");
    if (!established) {
        return fails;
    }

    constexpr U8 kLargeUnreliableType = 33;
    constexpr U8 kLargeUnreliableEchoType = 133;
    constexpr U8 kLargeOrderedType = 34;
    constexpr U8 kLargeOrderedEchoType = 134;

    const auto large_unreliable = make_payload(NetConfig::MaxMessageBytes + 600, 5);
    const auto large_ordered = make_payload(NetConfig::MaxOrderedMessageBytes + 700, 19);

    bool server_got_large_unreliable = false;
    bool server_got_large_ordered = false;
    bool client_got_unreliable_echo = false;
    bool client_got_ordered_echo = false;

    srv.on_message([&](Server::Peer peer, const MsgView& msg) {
        if (msg.channel == Channel::Unreliable && msg.type == kLargeUnreliableType && bytes_match(msg, large_unreliable)) {
            server_got_large_unreliable = true;
            (void)peer.send(Channel::Unreliable,
                            kLargeUnreliableEchoType,
                            std::span<const U8>(large_unreliable.data(), large_unreliable.size()));
        }
        if (msg.channel == Channel::ReliableOrdered && msg.type == kLargeOrderedType && bytes_match(msg, large_ordered)) {
            server_got_large_ordered = true;
            SendOptions options{};
            options.channel = Channel::ReliableOrdered;
            (void)peer.send(options,
                            kLargeOrderedEchoType,
                            std::span<const U8>(large_ordered.data(), large_ordered.size()));
        }
    });

    cli.on_message([&](const MsgView& msg) {
        if (msg.channel == Channel::Unreliable && msg.type == kLargeUnreliableEchoType && bytes_match(msg, large_unreliable)) {
            client_got_unreliable_echo = true;
        }
        if (msg.channel == Channel::ReliableOrdered && msg.type == kLargeOrderedEchoType && bytes_match(msg, large_ordered)) {
            client_got_ordered_echo = true;
        }
    });

    SendOptions unreliable_options{};
    unreliable_options.channel = Channel::Unreliable;
    rc = cli.send(unreliable_options, kLargeUnreliableType,
                  std::span<const U8>(large_unreliable.data(), large_unreliable.size()));
    fails += expect(rc.ok(), "fragment transport: client large unreliable send failed");

    SendOptions ordered_options{};
    ordered_options.channel = Channel::ReliableOrdered;
    rc = cli.send(ordered_options, kLargeOrderedType,
                  std::span<const U8>(large_ordered.data(), large_ordered.size()));
    fails += expect(rc.ok(), "fragment transport: client large ordered send failed");

    const bool exchanged = pump_until(srv, cli, 1500, [&] {
        return server_got_large_unreliable && server_got_large_ordered &&
               client_got_unreliable_echo && client_got_ordered_echo;
    });
    fails += expect(exchanged, "fragment transport: fragmented message exchange did not complete");

    const auto& client_stats = cli.stats();
    const auto& server_stats = srv.stats();
    fails += expect(client_stats.fragmented_messages_sent >= 2, "fragment transport: client should count fragmented messages sent");
    fails += expect(client_stats.fragments_sent >= 4, "fragment transport: client should count sent fragments");
    fails += expect(client_stats.reassemblies_completed >= 2, "fragment transport: client should count completed reassemblies");
    fails += expect(server_stats.fragmented_messages_received >= 2, "fragment transport: server should count fragmented messages received");
    fails += expect(server_stats.fragments_received >= 2, "fragment transport: server should count received fragments");
    fails += expect(server_stats.reassemblies_completed >= 2, "fragment transport: server should count completed reassemblies");

    (void)cli.close(CloseReason::Normal);
    (void)pump_until(srv, cli, 300, [&] { return cli.state() == ConnectionState::Closed || srv.peer_count() == 0; });
    cli.stop();
    srv.stop();
    return fails;
}
