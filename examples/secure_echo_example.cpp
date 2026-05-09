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

    ServerRouter router;
    router.on_text(kEchoType, [&](Server::Peer peer, std::string_view text) {
        std::printf("[server] conn=%llu echo len=%zu\n",
                    static_cast<unsigned long long>(peer.conn_id()),
                    text.size());
        return peer.send_ordered_text(kEchoType, text);
    });
    router.attach(srv);

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

    bool got_echo = false;
    std::string echoed{};

    ClientRouter router;
    router.on_text(kEchoType, [&](std::string_view text) {
        echoed.assign(text);
        got_echo = true;
    });
    router.attach(cli);

    cli.on_connected([&] {
        auto send_rc = cli.send_ordered_text(kEchoType, message);
        if (!send_rc.ok()) {
            std::printf("send failed: err=%u msg=%.*s\n",
                        static_cast<unsigned>(send_rc.code),
                        static_cast<int>(send_rc.msg.size()),
                        send_rc.msg.data());
        }
        (void)send_rc;
    });

    const bool completed = scn_examples::pump_until(cli, 2500, [&] {
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
