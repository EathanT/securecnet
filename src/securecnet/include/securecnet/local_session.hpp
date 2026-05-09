#pragma once

#include <string_view>

#include "securecnet/client.hpp"
#include "securecnet/io_context.hpp"
#include "securecnet/server.hpp"

namespace scn {

    class LocalSession {
    public:
        LocalSession() : _server(_io), _client(_io) {}
        LocalSession(const ServerConfig& server_config, const ClientConfig& client_config)
            : _server(server_config, _io), _client(client_config, _io) {}
        ~LocalSession() { stop(); }

        LocalSession(const LocalSession&) = delete;
        LocalSession& operator=(const LocalSession&) = delete;

        Result listen_and_connect(U16 port, std::string_view host = "127.0.0.1") {
            auto rc = _server.listen(port);
            if (!rc.ok()) {
                return rc;
            }
            rc = _client.connect(host, port);
            if (!rc.ok()) {
                _server.stop();
                return rc;
            }
            rc = _io.run_async();
            if (_io.running() || rc.code == Errc::StateError) {
                return Result::success();
            }
            return rc;
        }

        void stop() {
            _io.stop();
            (void)_io.join();
        }

        IoContext& io_context() { return _io; }
        const IoContext& io_context() const { return _io; }
        Server& server() { return _server; }
        const Server& server() const { return _server; }
        Client& client() { return _client; }
        const Client& client() const { return _client; }

    private:
        IoContext _io{};
        Server _server;
        Client _client;
    };

} // namespace scn
