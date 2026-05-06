#include "example_common.hpp"

#include <cstdlib>
#include <cstring>
#include <string>

using namespace scn;

namespace {
constexpr U8 kLargeType = 9;
constexpr ST kDefaultSize = 4096;
}

static void usage() {
    std::printf(
        "Usage:\n"
        "  large_message_example --server <port>\n"
        "  large_message_example --client <host> <port> [bytes]\n");
}

static int run_server(const char* port) {
    Server srv;
    auto rc = srv.listen(port);
    if (!rc.ok()) {
        return scn_examples::print_result("server.listen", rc);
    }
    Endpoint local{};
    rc = srv.local_endpoint(local);
    if (!rc.ok()) {
        return scn_examples::print_result("server.local_endpoint", rc);
    }
    std::printf("large message server listening on %s\n", local.to_string().c_str());

    srv.on_message([&](Server::Peer peer, const MsgView& msg) {
        if (msg.type != kLargeType) {
            return;
        }
        std::printf("[server] received %u bytes on channel %u\n",
                    static_cast<unsigned>(msg.len),
                    static_cast<unsigned>(msg.channel));
        SendOptions options{};
        options.channel = Channel::ReliableOrdered;
        (void)peer.send(options, kLargeType, msg.bytes());
    });

    while (true) {
        rc = srv.tick();
        if (!rc.ok()) {
            return scn_examples::print_result("server.tick", rc);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static int run_client(const char* host, const char* port, ST payload_size) {
    Client cli;
    auto rc = cli.connect(host, port);
    if (!rc.ok()) {
        return scn_examples::print_result("client.connect", rc);
    }

    const auto payload = scn_examples::make_pattern_payload(payload_size, 23);
    bool sent = false;
    bool matched = false;

    cli.on_message([&](const MsgView& msg) {
        if (msg.type != kLargeType) {
            return;
        }
        matched = (msg.len == payload.size()) && (std::memcmp(msg.data, payload.data(), payload.size()) == 0);
    });

    const bool completed = scn_examples::pump_until(cli, 5000, [&] {
        if (!sent && cli.state() == ConnectionState::Established) {
            SendOptions options{};
            options.channel = Channel::ReliableOrdered;
            auto send_rc = cli.send(options, kLargeType,
                                    std::span<const U8>(payload.data(), payload.size()));
            if (!send_rc.ok()) {
                std::printf("send failed: err=%u msg=%.*s\n",
                            static_cast<unsigned>(send_rc.code),
                            static_cast<int>(send_rc.msg.size()),
                            send_rc.msg.data());
                return true;
            }
            sent = true;
        }
        return matched || cli.state() == ConnectionState::Closed;
    });

    if (!completed || !matched) {
        std::printf("large message exchange did not complete successfully\n");
        return 1;
    }

    std::printf("large message round-trip complete: %zu bytes\n", payload.size());
    (void)cli.close(CloseReason::Normal);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        usage();
        return 1;
    }
    const std::string mode = argv[1];
    if (mode == "--server" && argc == 3) {
        return run_server(argv[2]);
    }
    if (mode == "--client" && (argc == 4 || argc == 5)) {
        const ST size = (argc == 5) ? static_cast<ST>(std::strtoull(argv[4], nullptr, 10)) : kDefaultSize;
        return run_client(argv[2], argv[3], size);
    }
    usage();
    return 1;
}
