#include "securecnet/scn.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <cstdlib>

namespace {
constexpr U8 kClientTextType = 1;
constexpr U8 kServerTextType = 200;
}


static void usage() {
    std::printf(
        "Usage:\n"
        "  net_smoketest --server <port>\n"
        "  net_smoketest --client <host> <port> [--count N] [--interval-ms M] [--message TEXT]\n"
        "\n"
        "Examples:\n"
        "  net_smoketest --server 27015\n"
        "  net_smoketest --client 127.0.0.1 27015 --count 3 --interval-ms 100 --message hello\n"
    );
}


static int run_server(const char* port_cstr) {
    scn::io_context ctx;
    if (!ctx.runtime_status().ok()) {
        std::printf("runtime init failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(ctx.runtime_status().code),
            static_cast<int>(ctx.runtime_status().msg.size()),
            ctx.runtime_status().msg.data());
        return 1;
    }

    scn::Server srv{ ctx };
    auto rc = srv.listen(port_cstr);
    if (!rc.ok()) {
        std::printf("server.local_endpoint failed: err %u msg=%.*s\n",
            static_cast<unsigned>(rc.code), static_cast<int>(rc.msg.size()), rc.msg.data()); 
        return 1;
    }

    scn::Endpoint local{};
    if (!rc.ok()) {
        std::printf("server.local_endpoint failed: err=%u msg %.*s\n",
            static_cast<unsigned>(rc.code), static_cast<int>(rc.msg.size()), rc.msg.data());
        return 1;
    }

    std::printf("Server listening on %s\n", local.to_string().c_str());
    std::fflush(stdout);

    srv.on_message([&](scn::Server::Peer peer, const scn::MsgView& msg) {
        std::printf("[server] from=%s conn_id=%llu type=%u len=%u data=\"%.*s\"\n",
            peer.endpoint().to_string().c_str(),
            static_cast<unsigned long long> (peer.conn_id()),
            static_cast<unsigned>(msg.type),
            static_cast<unsigned>(msg.len),
            static_cast<int>(msg.text().size()),
            msg.text().data()
        );

        std::fflush(stdout);

        if (msg.type != kClientTextType) {
            return;
        }

        const std::string reply = "echo:" + std::string(msg.text());
        auto reply_rc = peer.send_text(kServerTextType, reply);
        if (!reply_rc.ok()) {
            std::printf("[server] send_text failed: err=%u msg=%.*s\n",
                static_cast<unsigned>(reply_rc.code),
                static_cast<int>(reply_rc.msg.size()),
                reply_rc.msg.data()
            );

            std::fflush(stdout);
        }
    });

    rc = ctx.run(); 
    if (!rc.ok()) {
        std::printf("context.run failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code), static_cast<int>(rc.msg.size()), rc.msg.data()
        );

        return 1;
    }

    return 0;
}

static int run_client(const char* host_cstr, const char* port_cstr, int count, int interval_ms,
    const std::string& message_text) {
    
    scn::io_context ctx;
    if (!ctx.runtime_status().ok()) {
        std::printf("runtime init failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(ctx.runtime_status().code),
            static_cast<int>(ctx.runtime_status().msg.size()),
            ctx.runtime_status().msg.data()
        );

        return 1;
    }

    scn::Client cli { ctx };
    auto rc = cli.connect(host_cstr, port_cstr);
    if (!rc.ok()) {
        std::printf("client.connect failed: err=%u msg=%.*s\n",
            static_cast<unsigned>(rc.code), static_cast<int>(rc.msg.size()), rc.msg.data()
        );

        return 1;
    }

    int echo_count = 0;
    cli.on_message([&](const scn::MsgView& msg) {
        const auto text = msg.text();
        std::printf("[client] type=%u len=%u data=\"%.*s\"\n",
            static_cast<unsigned>(msg.type),
            static_cast<unsigned>(msg.len),
            static_cast<int>(text.size()),
            text.data()
        );

        std::fflush(stdout);

        const std::string expected_reply = "echo:" + message_text;
        if (msg.type == kServerTextType && text == expected_reply) {
            ++echo_count;
        }
    });
   
    for (int i = 0; i < count; ++i) {
        std::printf("[client] sending message %d/%d: \"%s\"\n",
            i + 1,
            count,
            message_text.c_str()
        );

        std::fflush(stdout);

        rc = cli.send_text(kClientTextType, message_text);
        if (!rc.ok()) {
            std::printf("client.send_text failed: err=%u msg=%u, msg=%.*s\n",
                static_cast<unsigned>(rc.code),
                static_cast<int>(rc.msg.size()),
				rc.msg.data()
            );

            return 1;
        }

        rc = ctx.run_for(std::chrono::milliseconds(interval_ms));
        if (!rc.ok()) {
            std::printf("context.run_for failed: err=%u msg=%u, msg=%.*s\n",
                static_cast<unsigned>(rc.code),
                static_cast<int>(rc.msg.size()),
                rc.msg.data()
            );

            return 1;
        }
    }

    rc = ctx.run_for(std::chrono::milliseconds(100));
    if (!rc.ok()) {
        std::printf("context.run_for failed during final drain: err=%u msg=%u, msg=%.*s\n",
            static_cast<unsigned>(rc.code),
            static_cast<int>(rc.msg.size()),
            rc.msg.data()
        );

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
    if (argc < 3) { usage(); return 1; }

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

        for (int i = 4; i < argc; ++i) {
            if (std::strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
                count = std::atoi(argv[++i]);
            }
            else if (std::strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
                interval_ms = std::atoi(argv[++i]);
            }
            else if (std::strcmp(argv[i], "--message") == 0 && i + 1 < argc) {
                message_text = argv[++i];
            }
        }

        return run_client(argv[2], argv[3], count, interval_ms, message_text);
    }

    usage();
    return 1;
}
