#include "securecnet/client.hpp"

#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"

#include <cstring>
#include <limits>
#include <string>

namespace scn {

    namespace {

        const Endpoint* prefer_ip4(const std::vector<Endpoint>& eps) {
            if (eps.empty()) {
                return nullptr;
            }

            for (const auto& ep : eps) {
                const auto* sa = reinterpret_cast<const sockaddr*>(&ep.addr);
                if (sa->sa_family == AF_INET) {
                    return&ep;
                }
            }

            return &eps.front();
        }

        bool endpoint_is_unspecified(const Endpoint& ep) {
            const auto* sa = reinterpret_cast<const sockaddr*>(&ep.addr);
            if (sa->sa_family == AF_INET) {
                return reinterpret_cast<const sockaddr_in*>(sa)->sin_addr.s_addr == htonl(INADDR_ANY);
            }

            if (sa->sa_family == AF_INET6) {
                return IN6_IS_ADDR_UNSPECIFIED(&reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr) != 0;
            }

            return false;
        }

        Endpoint normalize_connect_endpoint(const Endpoint& ep) {
            if (!endpoint_is_unspecified(ep)) {
                return ep;
            }

            Endpoint normalized = ep;
            auto* sa = reinterpret_cast<sockaddr*>(&normalized.addr);
            if (sa->sa_family == AF_INET) {
                reinterpret_cast<sockaddr_in*>(sa)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            }
            else if (sa->sa_family == AF_INET6) {
                reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr = in6addr_loopback;
            }

            return normalized;
        }

    }

    Client::Client(IoContext& ctx) : _ctx(&ctx) {
        _ctx->register_service(this);
    }

    Client::~Client() {
        stop();
        if (_ctx) {
            _ctx->unregister_service(this);
        }
    }

    Result Client::runtime_status() const {
        return _ctx ? _ctx->runtime_status() : _runtime.status();
    }

    Result Client::connect(const Endpoint& server) {
        if (!runtime_status().ok()) {
            return runtime_status();
        }

        stop();
        _server = normalize_connect_endpoint(server);

        const int family = reinterpret_cast<const sockaddr*>(&_server.addr)->sa_family;
        auto rc = _sock.open(family);
        if (!rc.ok()) {
            return rc;
        }

        rc = _sock.connect(_server);
        if (!rc.ok()) {
            return rc;
        }

        rc = _sock.set_nonblocking(true);
        if (!rc.ok()) {
            return rc;
        }

        _seq = 1;
        _pending.clear();
        return Result::success();
    }

    Result Client::connect(std::string_view host, std::string_view port) {
        std::vector<Endpoint> eps; 
        auto rc = resolve_endpoints(host, port, false, eps);
        if (!rc.ok()) {
            return rc;
        }

        const Endpoint* server = prefer_ip4(eps);
        if (!server) {
            return Result::fail(Errc::ResolveError, "no endpoints returned");
        }

        return connect(*server);
    }

    Result Client::connect(std::string_view host, U16 port) {
        return connect(host, std::to_string(port));
    }

    void Client::stop() {
        _pending.clear();
        _sock.close();
    }

    Result Client::send_payload(const U8* data, ST len) {
        return queue_payload(data, len);
    }

    Result Client::send_payload(std::span<const U8> payload) {
        return queue_payload(payload.data(), payload.size());
    }

    Result Client::send_message(Channel channel, U8 type, const void* data, U16 len) {
        std::array<U8, NetConfig::MaxPacketBytes> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_message(writer, channel, type, data, len);
        if (!rc.ok()) {
            return rc;
        }

        return queue_payload(payload.data(), writer.off);
    }

    Result Client::send(Channel channel, U8 type, std::span<const U8> payload) {
        if (payload.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::InvalidArg, "message payload too large");
        }

        return send_message(channel, type, payload.data(), static_cast<U16>(payload.size()));
    }

    Result Client::send_text(U8 type, std::string_view text) {
        if (text.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::InvalidArg, "text payload too large");
        }

        return send_message(Channel::Unreliable, type, text.data(), static_cast<U16>(text.size()));
    }

    Result Client::queue_payload(const U8* data, ST len) {
        if (len > NetConfig::MaxPacketBytes) {
            return Result::fail(Errc::InvalidArg, "payload too large");
        }

        PacketHeader header{};
        header.flags = 0;
        header.conn_id = _conn_id;
        header.seq = _seq++;

        PendingPacket pending{};
        auto rc = pack_packet(header, data, len, pending.bytes.data(), pending.bytes.size(), pending.len); 
        if (!rc.ok()) {
            return rc;
        }

        _pending.push_back(std::move(pending));
        
        return flush_pending();
    }

    Result Client::flush_pending() {
        while (!_pending.empty()) {
            const PendingPacket& pending = _pending.front();
            auto rc = _sock.send(pending.bytes.data(), pending.len);
            if (!rc.ok()) {
                if (rc.code == Errc::WouldBlock) {
                    return Result::success();
                }
                return rc;
            }

            _pending.pop_front();
        }

        return Result::success();
    }

    void Client::dispatch_packet_inline(const U8* data, ST len) {
        PacketView packet{};
        auto rc = parse_packet(data, len, packet);
        if (!rc.ok()) {
            return;
        }

        if (_on_packet) {
            _on_packet(packet);
        }

        if (_on_message) {
            ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
            for (;;) {
                MsgView msg{};
                auto msg_rc = read_message(reader, msg);
                if (msg_rc.code == Errc::EndOfStream) {
                    break;
                }
                if (!msg_rc.ok()) {
                    break;
                }

                _on_message(msg);
            }
        }
    }

    void Client::dispatch_packet_deferred(std::vector <U8> data) {
        auto packet_handler = _on_packet;
        auto message_handler = _on_message;
        _ctx->post([packet_handler = std::move(packet_handler), message_handler = std::move(message_handler), data = std::move(data)]() mutable {
            PacketView packet{};
            auto rc = parse_packet(data.data(), data.size(), packet);
            if (!rc.ok()) {
                return;
            }

            if (packet_handler) {
                packet_handler(packet);
            }

            if (message_handler) {
                ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
                for (;;) {
                    MsgView msg{};
                    auto msg_rc = read_message(reader, msg);
                    if (msg_rc.code == Errc::EndOfStream) {
                        break;
                    }
                    if (!msg_rc.ok()) {
                        break;
                    }

                    message_handler(msg);
                }
            }
        });
    }

    Result Client::pump_receive() {
        for (;;) {
            ST n = 0;
            auto rc = _sock.recv(_rxbuf, sizeof(_rxbuf), n);
            if (!rc.ok()) {
                if (rc.code == Errc::WouldBlock) {
                    break;
                }
                if (rc.code == Errc::Truncated) {
                    continue;
                }
                return rc;
            }

            if (_ctx) {
                std::vector<U8> packet(n);
                std::memcpy(packet.data(), _rxbuf, n);
                dispatch_packet_deferred(std::move(packet));
            }
            else {
                dispatch_packet_inline(_rxbuf, n);
            }
        }

        return Result::success();
    }

    Result Client::tick() {
        auto rc = flush_pending();
        if (!rc.ok()) {
            return rc;
        }

        return pump_receive();
    }

    Result Client::context_poll() {
        return tick(); 
    }

    Result Client::local_endpoint(Endpoint& out) const {
        return _sock.local_endpoint(out);
    }

}
