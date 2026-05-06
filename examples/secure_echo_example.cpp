#include "example_common.hpp"

#include <cstdlib>
#include <string>

using namespace scn;

namespace {
constexpr U8 kEchoType = 1;
}

static void usage() {
    std::printf(
        "Usage:\n"
        "  secure_echo_example --server <port>\n"
        "  secure_echo_example --client <host> <port> <message>\n");
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

    std::printf("secure echo server listening on %s\n", local.to_string().c_str());

    srv.on_message([&](Server::Peer peer, const MsgView& msg) {
        std::printf("[server] conn=%llu channel=%u type=%u len=%u\n",
                    static_cast<unsigned long long>(peer.conn_id()),
                    static_cast<unsigned>(msg.channel),
                    static_cast<unsigned>(msg.type),
                    static_cast<unsigned>(msg.len));
        (void)peer.send(Channel::ReliableOrdered, kEchoType, msg.bytes());
    });

    while (true) {
        rc = srv.tick();
        if (!rc.ok()) {
            return scn_examples::print_result("server.tick", rc);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static int run_client(const char* host, const char* port, const char* message) {
    Client cli;
    auto rc = cli.connect(host, port);
    if (!rc.ok()) {
        return scn_examples::print_result("client.connect", rc);
    }

    bool sent = false;
    bool got_echo = false;
    std::string echoed{};

    cli.on_message([&](const MsgView& msg) {
        if (msg.type == kEchoType) {
            echoed.assign(msg.text());
            got_echo = true;
        }
    });

    const bool completed = scn_examples::pump_until(cli, 2500, [&] {
        if (!sent && cli.state() == ConnectionState::Established) {
            SendOptions options{};
            options.channel = Channel::ReliableOrdered;
            auto send_rc = cli.send(options,
                                    kEchoType,
                                    std::span<const U8>(reinterpret_cast<const U8*>(message), std::strlen(message)));
            if (!send_rc.ok()) {
                std::printf("send failed: err=%u msg=%.*s\n",
                            static_cast<unsigned>(send_rc.code),
                            static_cast<int>(send_rc.msg.size()),
                            send_rc.msg.data());
                return true;
            }
            sent = true;
        }
        return got_echo || cli.state() == ConnectionState::Closed;
    });

    if (!completed || !got_echo) {
        std::printf("echo not received before timeout; state=%u reason=%u\n",
                    static_cast<unsigned>(cli.state()),
                    static_cast<unsigned>(cli.close_reason()));
        return 1;
    }

    std::printf("echo reply: %s\n", echoed.c_str());
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
    if (mode == "--client" && argc == 5) {
        return run_client(argv[2], argv[3], argv[4]);
    }
    usage();
    return 1;
}
