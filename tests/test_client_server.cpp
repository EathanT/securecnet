#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"
#include "securecnet/client.hpp"
#include "securecnet/message.hpp"
#include "securecnet/server.hpp"
#include "securecnet/socket_init.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <string>

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


int test_client_server() {
    int fails = 0;

    io_context ctx;
    if (!ctx.runtime_status().ok()) {
        std::printf(" runtime init failed\n");
        return 1;
    }

    Server srv(ctx);
    auto rc = srv.listen(0);
    if (!rc.ok()) {
        std::printf(" server.listen failed\n");
        return 1;
    }

    Endpoint server_local{};
    rc = srv.local_endpoint(server_local);
    if (!rc.ok()) {
        std::printf(" src.local_endpoint failed\n");
        return 1;
    }

    Client cli{ ctx };
    rc = cli.connect(server_local);
    if (!rc.ok()) {
        std::printf(" client.connect failed\n");
        return 1;
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
        std::printf(" cli.send_text faield\n");
        return 1;
    }

    const auto request_bytes = std::span<const U8>(reinterpret_cast<const U8*>(request_text.data()), request_text.size());
    rc = cli.send(Channel::Reliable, kClientTextType, request_bytes);
    if (!rc.ok()) {
        std::printf(" ctx.send reliable failed\n");
        return 1;
    }


    rc = ctx.run_for(std::chrono::milliseconds(200));
    if (!rc.ok()) {
        std::printf(" ctx.run_for failed\n");
        return 1;
    }

    fails += expect(server_got_text, "server never received client text");
    fails += expect(client_got_echo, "client never received echoed text");
    fails += expect(server_got_reliable, "server never received reliable client text");
    fails += expect(client_got_reliable, "client never received reliable echoed text");


    cli.stop();
    srv.stop();
    return fails;
}
