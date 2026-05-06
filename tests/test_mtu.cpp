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
        payload[i] = static_cast<U8>((static_cast<U32>(seed) + static_cast<U32>(i * 5u)) % 251u);
    }
    return payload;
}

static bool bytes_match(const MsgView& msg, const std::vector<U8>& expected) {
    return msg.len == expected.size() && std::memcmp(msg.data, expected.data(), expected.size()) == 0;
}

int test_mtu() {
    int fails = 0;

    ClientConfig client_cfg{};
    client_cfg.fragmentation.max_reassembled_message_bytes = 4096;
    client_cfg.fragmentation.max_total_reassembly_memory_per_peer = 4096;
    ServerConfig server_cfg{};
    server_cfg.fragmentation.max_reassembled_message_bytes = 4096;
    server_cfg.fragmentation.max_total_reassembly_memory_per_peer = 4096;
    server_cfg.abuse.max_total_reassembly_memory_server = 8192;

    Server srv{ server_cfg };
    auto rc = srv.listen(0);
    if (!rc.ok()) {
        std::printf(" mtu: server.listen failed\n");
        return 1;
    }

    Endpoint server_local{};
    if (!srv.local_endpoint(server_local).ok()) {
        std::printf(" mtu: server.local_endpoint failed\n");
        return 1;
    }

    Client cli{ client_cfg };
    if (!cli.connect(server_local).ok()) {
        std::printf(" mtu: client.connect failed\n");
        return 1;
    }

    const bool established = pump_until(srv, cli, 500, [&] {
        return cli.state() == ConnectionState::Established && srv.peer_count() == 1;
    });
    fails += expect(established, "mtu: client/server handshake never established");
    if (!established) {
        return fails;
    }

    constexpr U8 kExactUnreliableType = 41;
    constexpr U8 kFragmentedUnreliableType = 42;
    constexpr U8 kExactOrderedType = 43;
    constexpr U8 kFragmentedOrderedType = 44;

    const auto exact_unreliable = make_payload(NetConfig::MaxMessageBytes, 1);
    const auto fragmented_unreliable = make_payload(NetConfig::MaxMessageBytes + 1, 2);
    const auto exact_ordered = make_payload(NetConfig::MaxOrderedMessageBytes, 3);
    const auto fragmented_ordered = make_payload(NetConfig::MaxOrderedMessageBytes + 1, 4);

    bool got_exact_unreliable = false;
    bool got_fragmented_unreliable = false;
    bool got_exact_ordered = false;
    bool got_fragmented_ordered = false;

    srv.on_message([&](Server::Peer, const MsgView& msg) {
        if (msg.type == kExactUnreliableType && msg.channel == Channel::Unreliable && bytes_match(msg, exact_unreliable)) {
            got_exact_unreliable = true;
        }
        if (msg.type == kFragmentedUnreliableType && msg.channel == Channel::Unreliable && bytes_match(msg, fragmented_unreliable)) {
            got_fragmented_unreliable = true;
        }
        if (msg.type == kExactOrderedType && msg.channel == Channel::ReliableOrdered && bytes_match(msg, exact_ordered)) {
            got_exact_ordered = true;
        }
        if (msg.type == kFragmentedOrderedType && msg.channel == Channel::ReliableOrdered && bytes_match(msg, fragmented_ordered)) {
            got_fragmented_ordered = true;
        }
    });

    rc = cli.send(Channel::Unreliable, kExactUnreliableType,
                  std::span<const U8>(exact_unreliable.data(), exact_unreliable.size()));
    fails += expect(rc.ok(), "mtu: exact unreliable payload should send without fragmentation");
    rc = cli.send(Channel::Unreliable, kFragmentedUnreliableType,
                  std::span<const U8>(fragmented_unreliable.data(), fragmented_unreliable.size()));
    fails += expect(rc.ok(), "mtu: over-MTU unreliable payload should send via fragmentation");
    rc = cli.send(Channel::ReliableOrdered, kExactOrderedType,
                  std::span<const U8>(exact_ordered.data(), exact_ordered.size()));
    fails += expect(rc.ok(), "mtu: exact ordered payload should send without fragmentation");
    rc = cli.send(Channel::ReliableOrdered, kFragmentedOrderedType,
                  std::span<const U8>(fragmented_ordered.data(), fragmented_ordered.size()));
    fails += expect(rc.ok(), "mtu: over-MTU ordered payload should send via fragmentation");

    const bool delivered = pump_until(srv, cli, 1000, [&] {
        return got_exact_unreliable && got_fragmented_unreliable && got_exact_ordered && got_fragmented_ordered;
    });
    fails += expect(delivered, "mtu: boundary payloads were not all delivered");

    const auto oversized = make_payload(client_cfg.fragmentation.max_reassembled_message_bytes + 1, 9);
    rc = cli.send(Channel::ReliableOrdered, 99,
                  std::span<const U8>(oversized.data(), oversized.size()));
    fails += expect(!rc.ok() && rc.code == Errc::TooLarge,
                    "mtu: payload above configured reassembly cap should be rejected");

    (void)cli.close(CloseReason::Normal);
    (void)pump_until(srv, cli, 300, [&] { return srv.peer_count() == 0 || cli.state() == ConnectionState::Closed; });
    cli.stop();
    srv.stop();
    return fails;
}
