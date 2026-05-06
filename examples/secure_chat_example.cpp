#include "example_common.hpp"

#include <atomic>
#include <deque>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

using namespace scn;

namespace {
constexpr U8 kChatType = 31;

struct ConsoleQueue {
    std::mutex mutex{};
    std::deque<std::string> lines{};
    std::atomic<bool> quit_requested{ false };
};

void start_input_thread(ConsoleQueue& queue) {
    std::thread([&queue]() {
        std::string line{};
        while (std::getline(std::cin, line)) {
            if (line == "/quit") {
                queue.quit_requested.store(true);
                break;
            }
            std::lock_guard<std::mutex> lock(queue.mutex);
            queue.lines.push_back(line);
        }
        queue.quit_requested.store(true);
    }).detach();
}

bool pop_line(ConsoleQueue& queue, std::string& line) {
    std::lock_guard<std::mutex> lock(queue.mutex);
    if (queue.lines.empty()) {
        return false;
    }
    line = std::move(queue.lines.front());
    queue.lines.pop_front();
    return true;
}

bool peer_gone(Result rc) {
    return rc.code == Errc::Closed || rc.code == Errc::StateError;
}

Result drain_client_close(Client& cli, CloseReason reason) {
    auto rc = cli.close(reason);
    if (!rc.ok()) {
        return rc;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    while (cli.state() != ConnectionState::Closed && std::chrono::steady_clock::now() < deadline) {
        rc = cli.tick();
        if (!rc.ok() && rc.code != Errc::Closed) {
            return rc;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return Result::success();
}

Result drain_server_close(Server& srv, const Server::Peer& peer) {
    auto rc = peer.close(CloseReason::Normal);
    if (!rc.ok() && !peer_gone(rc)) {
        return rc;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    while (std::chrono::steady_clock::now() < deadline) {
        rc = srv.tick();
        if (!rc.ok()) {
            return rc;
        }
        if (srv.peer_count() == 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    return Result::success();
}
}

static void usage() {
    std::printf(
        "Usage:\n"
        "  secure_chat_example --server <port>\n"
        "  secure_chat_example --client <host> <port>\n"
        "Type /quit to exit.\n");
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
    std::printf("secure chat server listening on %s\n", local.to_string().c_str());
    std::printf("Type chat lines and press Enter. /quit exits.\n");

    ConsoleQueue console{};
    start_input_thread(console);

    Server::Peer active_peer{};
    bool have_peer = false;
    srv.on_message([&](Server::Peer peer, const MsgView& msg) {
        if (msg.type != kChatType) {
            return;
        }
        active_peer = peer;
        have_peer = true;
        std::printf("[client] %.*s\n", static_cast<int>(msg.text().size()), msg.text().data());
    });

    while (!console.quit_requested.load()) {
        rc = srv.tick();
        if (!rc.ok()) {
            return scn_examples::print_result("server.tick", rc);
        }

        std::string line{};
        while (pop_line(console, line)) {
            if (!have_peer) {
                std::printf("[server] no connected client; message not sent\n");
                continue;
            }

            SendOptions options{};
            options.channel = Channel::ReliableOrdered;
            auto send_rc = active_peer.send(options,
                                            kChatType,
                                            std::span<const U8>(reinterpret_cast<const U8*>(line.data()), line.size()));
            if (!send_rc.ok()) {
                if (peer_gone(send_rc)) {
                    std::printf("[server] client disconnected; message not sent\n");
                    active_peer = Server::Peer{};
                    have_peer = false;
                    continue;
                }
                std::printf("server send failed: err=%u msg=%.*s\n",
                            static_cast<unsigned>(send_rc.code),
                            static_cast<int>(send_rc.msg.size()),
                            send_rc.msg.data());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    if (have_peer) {
        rc = drain_server_close(srv, active_peer);
        if (!rc.ok()) {
            return scn_examples::print_result("server.close", rc);
        }
    }

    return 0;
}

static int run_client(const char* host, const char* port) {
    Client cli;
    auto rc = cli.connect(host, port);
    if (!rc.ok()) {
        return scn_examples::print_result("client.connect", rc);
    }
    std::printf("connected chat client; waiting for session establishment...\n");
    std::printf("Type chat lines and press Enter. /quit exits.\n");

    ConsoleQueue console{};
    start_input_thread(console);

    cli.on_message([&](const MsgView& msg) {
        if (msg.type == kChatType) {
            std::printf("[server] %.*s\n", static_cast<int>(msg.text().size()), msg.text().data());
        }
    });

    while (!console.quit_requested.load()) {
        rc = cli.tick();
        if (!rc.ok()) {
            return scn_examples::print_result("client.tick", rc);
        }

        if (cli.state() == ConnectionState::Established) {
            std::string line{};
            while (pop_line(console, line)) {
                SendOptions options{};
                options.channel = Channel::ReliableOrdered;
                auto send_rc = cli.send(options,
                                        kChatType,
                                        std::span<const U8>(reinterpret_cast<const U8*>(line.data()), line.size()));
                if (!send_rc.ok()) {
                    std::printf("client send failed: err=%u msg=%.*s\n",
                                static_cast<unsigned>(send_rc.code),
                                static_cast<int>(send_rc.msg.size()),
                                send_rc.msg.data());
                }
            }
        }
        if (cli.state() == ConnectionState::Closed) {
            std::printf("connection closed: reason=%u\n", static_cast<unsigned>(cli.close_reason()));
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    rc = drain_client_close(cli, CloseReason::Normal);
    if (!rc.ok()) {
        return scn_examples::print_result("client.close", rc);
    }
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
    if (mode == "--client" && argc == 4) {
        return run_client(argv[2], argv[3]);
    }
    usage();
    return 1;
}
