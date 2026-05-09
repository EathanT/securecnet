#include "example_common.hpp"

#include <chrono>
#include <cstdlib>
#include <future>
#include <optional>
#include <string>

using namespace scn;

namespace {
constexpr U8 kLookupType = 11;
}

static void usage() {
    std::printf(
        "Usage:\n"
        "  request_reply_example --server <port>\n"
        "  request_reply_example --client <host> <port> <key>\n");
}

static int run_server(const char* port) {
    Server server;
    auto rc = server.listen(port);
    if (!rc.ok()) {
        return scn_examples::print_result("server.listen", rc);
    }

    ServerRouter router;
    router.on(RequestReplyDefaultMessageType, [&](Server::Peer peer, const MsgView& msg) -> Result {
        RequestReplyFrame request{};
        auto parse_rc = read_request_reply_frame(msg, request);
        if (!parse_rc.ok()) {
            return parse_rc;
        }
        if (request.kind != RequestReplyKind::Request || request.type != kLookupType) {
            return send_error_response(peer, request, "unsupported request");
        }

        std::string key(request.text());
        std::string value = "value-for-" + key;
        auto bytes = std::span<const U8>(reinterpret_cast<const U8*>(value.data()), value.size());
        return send_response(peer, request, bytes);
    });
    router.attach(server);

    auto local = server.local_endpoint();
    if (local.ok()) {
        std::printf("request/reply server listening on %s\n", local.value.to_string().c_str());
    }

    while (true) {
        rc = server.tick();
        if (!rc.ok()) {
            return scn_examples::print_result("server.tick", rc);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static int run_client(const char* host, const char* port, const char* key) {
    Client client;
    ClientRouter router;
    ClientRequestTable requests;
    std::optional<std::future<ResultT<std::vector<U8>>>> pending;

    router.on(RequestReplyDefaultMessageType, [&](const MsgView& msg) -> Result {
        return requests.dispatch(msg).rc;
    });
    router.attach(client);

    client.on_connected([&] {
        auto payload = std::span<const U8>(reinterpret_cast<const U8*>(key), std::strlen(key));
        auto future = requests.request(client, kLookupType, payload, 2500);
        if (future.ok()) {
            pending.emplace(std::move(future.value));
        } else {
            std::printf("request failed to start: %.*s\n",
                        static_cast<int>(future.msg.size()),
                        future.msg.data());
        }
    });

    auto rc = client.connect(host, port);
    if (!rc.ok()) {
        return scn_examples::print_result("client.connect", rc);
    }

    const bool completed = scn_examples::pump_until(client, 3000, [&] {
        requests.expire();
        return (pending && pending->wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) ||
               client.state() == ConnectionState::Closed;
    });

    if (!completed || !pending) {
        std::printf("request did not complete\n");
        return 1;
    }

    auto reply = pending->get();
    if (!reply.ok()) {
        std::printf("request failed: %.*s\n", static_cast<int>(reply.msg.size()), reply.msg.data());
        return 1;
    }

    std::string text(reinterpret_cast<const char*>(reply.value.data()), reply.value.size());
    std::printf("reply: %s\n", text.c_str());
    (void)client.close();
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
