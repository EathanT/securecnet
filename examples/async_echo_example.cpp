#include "example_common.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <future>
#include <mutex>
#include <string>
#include <thread>

using namespace scn;

namespace {
constexpr U8 kRequestType = 61;
constexpr U8 kReplyType = 161;
}

template <class Predicate>
bool wait_until_on_context(IoContext& ctx, int timeout_ms, Predicate&& predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto future = ctx.post_task([&predicate]() mutable { return predicate(); });
        if (future.wait_for(std::chrono::milliseconds(250)) == std::future_status::ready && future.get()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

int main() {
    IoContext ctx;
    Server server(ctx);
    Client client(ctx);

    const std::string request = "hello from async securecnet";
    const std::string reply = "echo: " + request;

    std::mutex mutex;
    std::condition_variable cv;
    bool echoed = false;

    server.on_message([&](Server::Peer peer, const MsgView& msg) {
        if (msg.type == kRequestType) {
            std::printf("server received: %.*s\n", static_cast<int>(msg.len), msg.data ? reinterpret_cast<const char*>(msg.data) : "");
            (void)peer.send_text(kReplyType, reply);
        }
    });

    client.on_message([&](const MsgView& msg) {
        if (msg.type == kReplyType && msg.text() == reply) {
            std::lock_guard<std::mutex> lock(mutex);
            echoed = true;
            cv.notify_all();
        }
    });

    auto rc = server.listen(0);
    if (!rc.ok()) {
        return scn_examples::print_result("server.listen", rc);
    }

    Endpoint server_endpoint{};
    rc = server.local_endpoint(server_endpoint);
    if (!rc.ok()) {
        return scn_examples::print_result("server.local_endpoint", rc);
    }

    rc = client.connect(server_endpoint);
    if (!rc.ok()) {
        return scn_examples::print_result("client.connect", rc);
    }

    rc = ctx.run_async();
    if (!rc.ok()) {
        return scn_examples::print_result("ctx.run_async", rc);
    }

    const bool established = wait_until_on_context(ctx, 1000, [&] {
        return client.state() == ConnectionState::Established && server.peer_count() == 1;
    });
    if (!established) {
        ctx.stop();
        (void)ctx.join();
        std::printf("async handshake did not establish\n");
        return 1;
    }

    auto send_future = ctx.post_task([&] { return client.send_text(kRequestType, request); });
    if (send_future.wait_for(std::chrono::milliseconds(500)) != std::future_status::ready) {
        ctx.stop();
        (void)ctx.join();
        std::printf("async send task timed out\n");
        return 1;
    }
    rc = send_future.get();
    if (!rc.ok()) {
        ctx.stop();
        (void)ctx.join();
        return scn_examples::print_result("client.send_text", rc);
    }

    {
        std::unique_lock<std::mutex> lock(mutex);
        if (!cv.wait_for(lock, std::chrono::seconds(1), [&] { return echoed; })) {
            ctx.stop();
            (void)ctx.join();
            std::printf("async echo timed out\n");
            return 1;
        }
    }

    auto close_future = ctx.post_task([&] { return client.close(CloseReason::Normal); });
    (void)close_future.wait_for(std::chrono::milliseconds(500));
    if (close_future.valid()) {
        (void)close_future.get();
    }
    ctx.stop();
    rc = ctx.join();
    if (!rc.ok()) {
        return scn_examples::print_result("ctx.join", rc);
    }

    std::printf("async echo complete\n");
    return 0;
}
