#include "securecnet/client.hpp"
#include "securecnet/io_context.hpp"
#include "securecnet/server.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <future>
#include <mutex>
#include <string>
#include <thread>

using namespace scn;

namespace {
constexpr U8 kAsyncRequestType = 51;
constexpr U8 kAsyncReplyType = 151;
}

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

static bool wait_for_future_bool(std::future<bool>& future, int timeout_ms) {
    if (future.wait_for(std::chrono::milliseconds(timeout_ms)) != std::future_status::ready) {
        return false;
    }
    return future.get();
}

template <class Predicate>
static bool wait_until_async(IoContext& ctx, int timeout_ms, Predicate&& predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto future = ctx.post_task([&predicate]() mutable { return predicate(); });
        if (wait_for_future_bool(future, 100)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    auto future = ctx.post_task([&predicate]() mutable { return predicate(); });
    return wait_for_future_bool(future, 100);
}

int test_async() {
    int fails = 0;

    {
        IoContext ctx;
        auto rc = ctx.run_async();
        fails += expect(rc.ok(), "async: run_async should start worker");
        rc = ctx.run_async();
        fails += expect(!rc.ok() && rc.code == Errc::StateError,
                        "async: second run_async should fail while worker is active");

        auto value = ctx.post_task([] { return 1234; });
        fails += expect(value.wait_for(std::chrono::milliseconds(500)) == std::future_status::ready,
                        "async: posted task did not complete");
        if (value.valid()) {
            fails += expect(value.get() == 1234, "async: posted task returned wrong value");
        }

        ctx.stop();
        rc = ctx.join();
        fails += expect(rc.ok(), "async: join should report clean shutdown");
        fails += expect(!ctx.running(), "async: context should not be running after join");

        rc = ctx.run_async();
        fails += expect(rc.ok(), "async: run_async should restart after join");
        auto stopper = ctx.post_task([&ctx] {
            ctx.stop();
            return true;
        });
        fails += expect(stopper.wait_for(std::chrono::milliseconds(500)) == std::future_status::ready,
                        "async: stopper task did not complete");
        if (stopper.valid()) {
            fails += expect(stopper.get(), "async: stopper task returned false");
        }
        rc = ctx.join();
        fails += expect(rc.ok(), "async: restarted context should join cleanly");
    }

    {
        IoContext ctx;
        Server srv(ctx);
        Client cli(ctx);

        const std::string request = "async-hello";
        const std::string reply = "async-echo:" + request;

        std::mutex mutex;
        std::condition_variable cv;
        bool server_received = false;
        bool client_received = false;

        srv.on_message([&](Server::Peer peer, const MsgView& msg) {
            if (msg.channel == Channel::Unreliable && msg.type == kAsyncRequestType && msg.text() == request) {
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    server_received = true;
                }
                (void)peer.send_text(kAsyncReplyType, reply);
                cv.notify_all();
            }
        });

        cli.on_message([&](const MsgView& msg) {
            if (msg.channel == Channel::Unreliable && msg.type == kAsyncReplyType && msg.text() == reply) {
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    client_received = true;
                }
                cv.notify_all();
            }
        });

        auto rc = srv.listen(0);
        fails += expect(rc.ok(), "async transport: server listen failed");
        Endpoint server_local{};
        rc = srv.local_endpoint(server_local);
        fails += expect(rc.ok(), "async transport: local endpoint failed");
        rc = cli.connect(server_local);
        fails += expect(rc.ok(), "async transport: client connect failed");
        if (!rc.ok()) {
            return fails;
        }

        rc = ctx.run_async();
        fails += expect(rc.ok(), "async transport: context worker failed to start");

        const bool established = wait_until_async(ctx, 750, [&] {
            return cli.state() == ConnectionState::Established && srv.peer_count() == 1;
        });
        fails += expect(established, "async transport: handshake did not establish");

        if (established) {
            auto send_future = ctx.post_task([&] { return cli.send_text(kAsyncRequestType, request); });
            fails += expect(send_future.wait_for(std::chrono::milliseconds(500)) == std::future_status::ready,
                            "async transport: send task did not complete");
            if (send_future.valid()) {
                rc = send_future.get();
                fails += expect(rc.ok(), "async transport: async send failed");
            }

            std::unique_lock<std::mutex> lock(mutex);
            const bool exchanged = cv.wait_for(lock, std::chrono::milliseconds(1000), [&] {
                return server_received && client_received;
            });
            fails += expect(exchanged, "async transport: echo exchange did not complete");
        }

        auto close_future = ctx.post_task([&] { return cli.close(CloseReason::Normal); });
        (void)close_future.wait_for(std::chrono::milliseconds(500));
        if (close_future.valid()) {
            (void)close_future.get();
        }
        ctx.stop();
        rc = ctx.join();
        fails += expect(rc.ok(), "async transport: context join failed");
        cli.stop();
        srv.stop();
    }

    return fails;
}
