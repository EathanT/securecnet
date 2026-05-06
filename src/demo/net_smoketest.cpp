#include "securecnet/scn.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
constexpr U8 kClientTextType = 1;
constexpr U8 kServerTextType = 200;
}

static void usage() {
    std::printf(
        "Usage:\n"
        "  net_smoketest --server <port>\n"
        "  net_smoketest --client <host> <port> [--count N] [--interval-ms M] [--message TEXT] [--reliable]\n"
        "  net_smoketest --help\n"
        "\n"
        "Examples:\n"
        "  net_smoketest --server 27015\n"
        "  net_smoketest --client 127.0.0.1 27015 --count 3 --interval-ms 100 --message hello\n"
        "  net_smoketest --client 127.0.0.1 27015 --reliable --message secure\n"
    );
}

static int run_server(const char* port_cstr) {
    scn::io_context ctx;
    const auto status = ctx.runtime_status();
    if (!status.ok()) {
        std::printf("runtime init failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(status.code),
            static_cast<int>(status.msg.size()),
            status.msg.data());
        return 1;
    }

    scn::Server srv{ ctx };
    auto rc = srv.listen(port_cstr);
    if (!rc.ok()) {
        std::printf("server.listen failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code),
            static_cast<int>(rc.msg.size()),
            rc.msg.data());
        return 1;
    }

    scn::Endpoint local{};
    rc = srv.local_endpoint(local);
    if (!rc.ok()) {
        std::printf("server.local_endpoint failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code),
            static_cast<int>(rc.msg.size()),
            rc.msg.data());
        return 1;
    }

    std::printf("Server listening on %s\n", local.to_string().c_str());
    std::fflush(stdout);

    srv.on_message([&](scn::Server::Peer peer, const scn::MsgView& msg) {
        std::printf("[server] from=%s conn_id=%llu channel=%u type=%u len=%u data=\"%.*s\"\n",
            peer.endpoint().to_string().c_str(),
            static_cast<unsigned long long>(peer.conn_id()),
            static_cast<unsigned>(msg.channel),
            static_cast<unsigned>(msg.type),
            static_cast<unsigned>(msg.len),
            static_cast<int>(msg.text().size()),
            msg.text().data());
        std::fflush(stdout);

        if (msg.type != kClientTextType) {
            return;
        }

        const std::string reply = "echo:" + std::string(msg.text());
        auto reply_bytes = std::span<const U8>(reinterpret_cast<const U8*>(reply.data()), reply.size());
        auto reply_rc = peer.send(msg.channel, kServerTextType, reply_bytes);
        if (!reply_rc.ok()) {
            std::printf("[server] send failed: err=%u msg=%.*s\n",
                static_cast<unsigned>(reply_rc.code),
                static_cast<int>(reply_rc.msg.size()),
                reply_rc.msg.data());
            std::fflush(stdout);
        }
    });

    rc = ctx.run();
    if (!rc.ok()) {
        std::printf("context.run failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code),
            static_cast<int>(rc.msg.size()),
            rc.msg.data());
        return 1;
    }

    return 0;
}

static int run_client(const char* host_cstr, const char* port_cstr, int count, int interval_ms,
    const std::string& message_text, bool reliable) {

    scn::io_context ctx;
    const auto status = ctx.runtime_status();
    if (!status.ok()) {
        std::printf("runtime init failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(status.code),
            static_cast<int>(status.msg.size()),
            status.msg.data());
        return 1;
    }

    scn::Client cli{ ctx };
    auto rc = cli.connect(host_cstr, port_cstr);
    if (!rc.ok()) {
        std::printf("client.connect failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code),
            static_cast<int>(rc.msg.size()),
            rc.msg.data());
        return 1;
    }

    int echo_count = 0;
    cli.on_message([&](const scn::MsgView& msg) {
        const auto text = msg.text();
        std::printf("[client] channel=%u type=%u len=%u data=\"%.*s\"\n",
            static_cast<unsigned>(msg.channel),
            static_cast<unsigned>(msg.type),
            static_cast<unsigned>(msg.len),
            static_cast<int>(text.size()),
            text.data());
        std::fflush(stdout);

        const std::string expected_reply = "echo:" + message_text;
        if (msg.type == kServerTextType && text == expected_reply &&
            msg.channel == (reliable ? scn::Channel::Reliable : scn::Channel::Unreliable)) {
            ++echo_count;
        }
    });

    const auto message_bytes = std::span<const U8>(reinterpret_cast<const U8*>(message_text.data()), message_text.size());

    rc = ctx.run_for(std::chrono::milliseconds(250));
    if (!rc.ok() || cli.state() != scn::ConnectionState::Established) {
        std::printf("client handshake failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code),
            static_cast<int>(rc.msg.size()),
            rc.msg.data());
        return 1;
    }

    for (int i = 0; i < count; ++i) {
        std::printf("[client] sending %s message %d/%d: \"%s\"\n",
            reliable ? "reliable" : "unreliable",
            i + 1,
            count,
            message_text.c_str());
        std::fflush(stdout);

        rc = reliable
            ? cli.send(scn::Channel::Reliable, kClientTextType, message_bytes)
            : cli.send_text(kClientTextType, message_text);
        if (!rc.ok()) {
            std::printf("client.send failed: err=%u msg=%.*s\n",
                static_cast<unsigned>(rc.code),
                static_cast<int>(rc.msg.size()),
                rc.msg.data());
            return 1;
        }

        rc = ctx.run_for(std::chrono::milliseconds(interval_ms));
        if (!rc.ok()) {
            std::printf("context.run_for failed: err=%u msg=%.*s\n",
                static_cast<unsigned>(rc.code),
                static_cast<int>(rc.msg.size()),
                rc.msg.data());
            return 1;
        }
    }

    rc = ctx.run_for(std::chrono::milliseconds(100));
    if (!rc.ok()) {
        std::printf("context.run_for failed during final drain: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code),
            static_cast<int>(rc.msg.size()),
            rc.msg.data());
        return 1;
    }

    if (echo_count != count) {
        std::printf("Smoke test failed: expected %d echo reply/replies, got %d\n", count, echo_count);
        std::fflush(stdout);
        return 1;
    }

    std::printf("Client done. Received %d/%d matching echo reply/replies.\n", echo_count, count);
    std::fflush(stdout);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--help") == 0)) {
        usage();
        return 0;
    }

    if (argc < 3) {
        usage();
        return 1;
    }

    if (std::strcmp(argv[1], "--server") == 0) {
        return run_server(argv[2]);
    }

    if (std::strcmp(argv[1], "--client") == 0) {
        if (argc < 4) {
            usage();
            return 1;
        }

        int count = 20;
        int interval_ms = 100;
        std::string message_text = "ping";
        bool reliable = false;

        for (int i = 4; i < argc; ++i) {
            if (std::strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
                count = std::atoi(argv[++i]);
            } else if (std::strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
                interval_ms = std::atoi(argv[++i]);
            } else if (std::strcmp(argv[i], "--message") == 0 && i + 1 < argc) {
                message_text = argv[++i];
            } else if (std::strcmp(argv[i], "--reliable") == 0) {
                reliable = true;
            }
        }

        return run_client(argv[2], argv[3], count, interval_ms, message_text, reliable);
    }

    usage();
    return 1;
}
