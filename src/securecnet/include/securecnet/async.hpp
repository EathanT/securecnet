#pragma once

#include <future>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

#include "securecnet/client.hpp"
#include "securecnet/server.hpp"

namespace scn {

    class AsyncClient {
    public:
        AsyncClient() : _client(_io) {}
        explicit AsyncClient(const ClientConfig& config) : _client(config, _io) {}
        ~AsyncClient() { stop(); }

        AsyncClient(const AsyncClient&) = delete;
        AsyncClient& operator=(const AsyncClient&) = delete;

        Result start() {
            if (_started) {
                return Result::success();
            }
            auto rc = _io.run_async();
            if (rc.ok()) {
                _started = true;
            }
            return rc;
        }

        void stop() {
            _io.stop();
            (void)_io.join();
            _started = false;
        }

        Client& client() { return _client; }
        const Client& client() const { return _client; }
        IoContext& io_context() { return _io; }

        std::future<Result> connect(const Endpoint& server) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, server] { return _client.connect(server); });
        }

        std::future<Result> connect(std::string_view host, U16 port) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, host = std::string(host), port] { return _client.connect(host, port); });
        }

        std::future<Result> send(const SendOptions& options, U8 type, std::span<const U8> payload) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            auto bytes = std::vector<U8>(payload.begin(), payload.end());
            return _io.post_task([this, options, type, bytes = std::move(bytes)] {
                return _client.send(options, type, std::span<const U8>(bytes.data(), bytes.size()));
            });
        }

        std::future<Result> send_text(U8 type, std::string_view text, const SendOptions& options = {}) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, type, text = std::string(text), options] {
                return _client.send_text(type, text, options);
            });
        }

        std::future<Result> send_unreliable_text(U8 type, std::string_view text) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, type, text = std::string(text)] {
                return _client.send_unreliable_text(type, text);
            });
        }

        std::future<Result> send_reliable_text(U8 type, std::string_view text, U64 lifetime_ms = 0) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, type, text = std::string(text), lifetime_ms] {
                return _client.send_reliable_text(type, text, SendPriority::Normal, lifetime_ms);
            });
        }

        std::future<Result> send_ordered_text(U8 type, std::string_view text, U64 lifetime_ms = 0) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, type, text = std::string(text), lifetime_ms] {
                return _client.send_ordered_text(type, text, SendPriority::Normal, lifetime_ms);
            });
        }

        std::future<Result> send_latest_text(U8 type, std::string_view text) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, type, text = std::string(text)] {
                return _client.send_latest_text(type, text);
            });
        }

        std::future<Result> close(CloseReason reason = CloseReason::Normal) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, reason] { return _client.close(reason); });
        }

    private:
        static std::future<Result> ready_result(Result rc) {
            std::promise<Result> promise;
            promise.set_value(rc);
            return promise.get_future();
        }

        IoContext _io{};
        Client _client;
        bool _started{ false };
    };

    class AsyncServer {
    public:
        AsyncServer() : _server(_io) {}
        explicit AsyncServer(const ServerConfig& config) : _server(config, _io) {}
        ~AsyncServer() { stop(); }

        AsyncServer(const AsyncServer&) = delete;
        AsyncServer& operator=(const AsyncServer&) = delete;

        Result start() {
            if (_started) {
                return Result::success();
            }
            auto rc = _io.run_async();
            if (rc.ok()) {
                _started = true;
            }
            return rc;
        }

        void stop() {
            _io.stop();
            (void)_io.join();
            _started = false;
        }

        Server& server() { return _server; }
        const Server& server() const { return _server; }
        IoContext& io_context() { return _io; }

        std::future<Result> listen(const Endpoint& endpoint) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, endpoint] { return _server.listen(endpoint); });
        }

        std::future<Result> listen(U16 port) {
            auto rc = start();
            if (!rc.ok()) {
                return ready_result(rc);
            }
            return _io.post_task([this, port] { return _server.listen(port); });
        }

        std::future<Result> close_peer(Server::Peer peer, CloseReason reason = CloseReason::Normal) {
            return _io.post_task([this, peer, reason] { return _server.close_peer(peer, reason); });
        }

    private:
        static std::future<Result> ready_result(Result rc) {
            std::promise<Result> promise;
            promise.set_value(rc);
            return promise.get_future();
        }

        IoContext _io{};
        Server _server;
        bool _started{ false };
    };

} // namespace scn
