#include "securecnet/server.hpp"

#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"

#include <cstring>
#include <limits>
#include <string>

namespace scn {

    namespace {

        const Endpoint* prefer_ipv4(const std::vector<Endpoint>& eps) {
            if (eps.empty()) {
                return nullptr; 
            }

            for (const auto& ep : eps) {
                const auto& sa = reinterpret_cast<const sockaddr*>(&ep.addr);
                if (sa->sa_family == AF_INET) {
                    return &ep;
                }
            }

            return &eps.front();
        }

    }

    Result Server::Peer::send_payload(const U8* data, ST len) const {
        if (!_owner) {
            return Result::fail(Errc::InvalidArg, "peer is not bound to a server");
        }

        return _owner->send_payload(*this, data, len);
    }

    Result Server::Peer::send_payload(std::span<const U8> payload) const {
        return send_payload(payload.data(), payload.size());
    }
    
    Result Server::Peer::send_message(Channel channel, U8 type, const void* data, U16 len) const {
        if (!_owner) {
            return Result::fail(Errc::InvalidArg, "peer is not bound to a server");
        }

        return _owner->send_message(*this, channel, type, data, len);
    }

    Result Server::Peer::send(Channel channel, U8 type, std::span<const U8> payload) const {
        if (payload.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::InvalidArg, "message payload too large");
        }

        return send_message(channel, type, payload.data(), static_cast<U16>(payload.size()));
    }

    Result Server::Peer::send_text(U8 type, std::string_view text) const {
        if (text.size() > static_cast<ST>(std::numeric_limits < U16>::max())) {
            return Result::fail(Errc::InvalidArg, "texdt payload too large");
        }

        return send_message(Channel::Unreliable, type, text.data(), static_cast<U16>(text.size()));
    }

    Server::Server(IoContext& ctx) : _ctx(&ctx) {
        _ctx->register_service(this);
    }

    Server::~Server() {
        stop();
        if (_ctx) {
            _ctx->unregister_service(this);
        }
    }

    Result Server::runtime_status() const {
        return _ctx ? _ctx->runtime_status() : _runtime.status();
    }

    Result Server::listen(const Endpoint& bind_ep) {
        if (!runtime_status().ok()) {
            return runtime_status();
        }

        stop();

        const int family = reinterpret_cast<const sockaddr*>(&bind_ep.addr)->sa_family;
        auto rc = _sock.open(family);
        if (!rc.ok()) {
            return rc;
        }
        
        rc = _sock.bind(bind_ep);
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

    Result Server::listen(std::string_view port) {
        std::vector<Endpoint> eps;
        auto rc = resolve_endpoints("", port, true, eps);
        if (!rc.ok()) {
            return rc;
        }

        const Endpoint* bind_ep = prefer_ipv4(eps);
        if (!bind_ep) {
            return Result::fail(Errc::ResolveError, "no endpoints returned");
        }

        return listen(*bind_ep);
    }

    Result Server::listen(U16 port) {
        return listen(std::to_string(port));
    }

    void Server::stop() {
        _pending.clear();
        _sock.close();
    }

    Result Server::queue_payload(const Endpoint& to, U64 conn_id, const U8* data, ST len) {
        if (len > (NetConfig::MaxPacketBytes)) {
            return Result::fail(Errc::InvalidArg, "payload too large");
        }

        PacketHeader header{};
        header.flags = 0;
        header.conn_id = conn_id;
        header.seq = _seq++;

        PendingPacket pending{};
        pending.to = to;
        auto rc = pack_packet(header, data, len, pending.bytes.data(), pending.bytes.size(), pending.len);
        if (!rc.ok()) {
            return rc;
        }

        _pending.push_back(std::move(pending));
        return flush_pending();
    }


    Result Server::send_payload(const Endpoint& to, U64 conn_id, const U8* data, ST len) {
        return queue_payload(to, conn_id, data, len);
    }

    Result Server::send_payload(const Peer& peer, const U8* data, ST len) {
        const U64 conn_id = (peer.conn_id() != 0) ? peer.conn_id() : 1;
        return queue_payload(peer.endpoint(), conn_id, data, len);
    }

    Result Server::send_payload(const Peer& peer, std::span<const U8> payload) {
        return send_payload(peer, payload.data(), payload.size());
    }

    Result Server::send_message(const Peer& peer, Channel channel, U8 type, const void* data, U16 len) {
        std::array<U8, NetConfig::MaxPacketBytes> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_message(writer, channel, type, data, len);
        if (!rc.ok()) {
            return rc;
        }

        return send_payload(peer, payload.data(), writer.off);
    }

    Result Server::send(const Peer& peer, Channel channel, U8 type, std::span<const U8> payload) {
        if (payload.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::InvalidArg, "message payload too large");
        }

        return send_message(peer, channel, type, payload.data(), static_cast<U16>(payload.size())); 
    }

    Result Server::send_text(const Peer& peer, U8 type, std::string_view text) {
        if (text.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::InvalidArg, "text payload too large");
        }

        return send_message(peer, Channel::Unreliable, type, text.data(), static_cast<U16>(text.size()));
    }

    Result Server::flush_pending() {
        while (!_pending.empty()) {
            const PendingPacket& pending = _pending.front();
            auto rc = _sock.send_to(pending.to, pending.bytes.data(), pending.len);
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

    void Server::dispatch_packet_inline(const Endpoint& from, const U8* data, ST len) {
        PacketView packet{};
        auto rc = parse_packet(data, len, packet);
        if (!rc.ok()) {
            return;
        }

        if (_on_packet) {
            _on_packet(from, packet);
        }

        if (_on_message) {
            Peer peer{ this, from, packet.h.conn_id };
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

                _on_message(peer, msg);
            }
        }
    }

    void Server::dispatch_packet_deferred(Endpoint from, std::vector<U8> data) {
        auto packet_handler = _on_packet;
        auto message_handler = _on_message;
        auto* owner = this;

        _ctx->post([packet_handler = std::move(packet_handler), message_handler = std::move(message_handler), from = std::move(from), data = std::move(data), owner]() mutable {
            PacketView packet{};
            auto rc = parse_packet(data.data(), data.size(), packet);
            if (!rc.ok()) {
                return; 
            }

            if (packet_handler) {
                packet_handler(from, packet);
            }

            if (message_handler) {
                Peer peer{ owner, from, packet.h.conn_id };
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

                    message_handler(peer, msg);
                }
            }

        });
    }


    Result Server::pump_receive() {
        for (;;) {
            Endpoint from{};
            ST n = 0;

            auto rc = _sock.recv_from(from, _rxbuf, sizeof(_rxbuf), n);
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
                dispatch_packet_deferred(std::move(from), std::move(packet));
            }
            else {
                dispatch_packet_inline(from, _rxbuf, n);
            }
        }

        return Result::success();
    }

    Result Server::tick() {
        auto rc = flush_pending();
        if (!rc.ok()) {
            return rc;
        }

        return pump_receive();
    }

    Result Server::context_poll() {
        return tick();
    }

    Result Server::local_endpoint(Endpoint& out) const {
        return _sock.local_endpoint(out);
    }

}
