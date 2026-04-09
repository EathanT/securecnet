#include "securecnet/client.hpp"

#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"

#include <chrono>
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
                    return &ep;
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

    U64 Client::now_ms() {
        return static_cast<U64>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
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
        _reliable.clear();
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
        _reliable.clear();
        _sock.close();
    }

    Result Client::send_payload(const U8* data, ST len) {
        return queue_payload(data, len);
    }

    Result Client::send_payload(std::span<const U8> payload) {
        return queue_payload(payload.data(), payload.size());
    }

    Result Client::queue_message_frame(Channel channel, U8 type, const void* data, U16 len) {
        std::array<U8, NetConfig::MaxPacketBytes> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_message(writer, channel, type, data, len);
        if (!rc.ok()) {
            return rc;
        }

        return queue_payload(payload.data(), writer.off);
    }

    Result Client::queue_control_ack(U64 message_id) {
        U8 ack_buf[sizeof(U64)]{};
        ByteWriter writer{ ack_buf, sizeof(ack_buf) };
        auto rc = write_reliable_ack(writer, message_id);
        if (!rc.ok()) {
            return rc;
        }

        return queue_message_frame(Channel::Control, static_cast<U8>(ControlType::ReliableAck), ack_buf,
                                   static_cast<U16>(writer.off));
    }

    Result Client::send_reliable_message(U8 type, const void* data, U16 len) {
        PendingReliableMessage pending{};
        auto rc = _reliable.enqueue(type, data, len, pending);
        if (!rc.ok()) {
            return rc;
        }

        rc = queue_message_frame(Channel::Reliable, type, pending.encoded_payload.data(),
            static_cast<U16>(pending.encoded_payload.size()));

        if (!rc.ok()) {
            _reliable.acknowledge(pending.message_id);
            return rc;
        }

        _reliable.note_sent(pending.message_id, now_ms());
        return Result::success();
    }

    Result Client::send_message(Channel channel, U8 type, const void* data, U16 len) {
        if (channel == Channel::Reliable) {
            return send_reliable_message(type, data, len);
        }

        return queue_message_frame(channel, type, data, len);
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

    Result Client::pump_reliable() {
        return _reliable.resend_due(now_ms(), NetConfig::ReliableResendDelayMs,
            [this](PendingReliableMessage& pending) {
                return queue_message_frame(Channel::Reliable, pending.user_type,
                    pending.encoded_payload.data(),
                    static_cast<U16>(pending.encoded_payload.size()));
            });
    }

    void Client::dispatch_message_frame(const MsgView& msg, const OnMessageFn& message_handler) {
        if (msg.channel == Channel::Control && msg.type == static_cast<U8>(ControlType::ReliableAck)) {
            ByteReader ack_reader{ msg.data, static_cast<ST>(msg.len) };
            U64 acked_message_id = 0;
            auto rc = read_reliable_ack(ack_reader, acked_message_id);
            if (rc.ok()) {
                _reliable.acknowledge(acked_message_id);
            }

            return;
        }

        if (msg.channel == Channel::Reliable) {
            ByteReader reliable_reader{ msg.data, static_cast<ST>(msg.len) };
            ReliablePayloadView reliable{};
            auto rc = read_reliable_payload(reliable_reader, reliable);
            if (!rc.ok()) {
                return;
            }

            (void)queue_control_ack(reliable.message_id);
            if (!_reliable.accept_incoming(reliable.message_id)) {
                return;
            }

            if (message_handler) {
                MsgView delivered{};
                delivered.channel = Channel::Reliable;
                delivered.type = msg.type;
                delivered.data = reliable.data;
                delivered.len = reliable.len;
                message_handler(delivered);
            }
            return;
        }

        if (message_handler) {
            message_handler(msg);
        }
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

                dispatch_message_frame(msg, _on_message);
            }
    }

    void Client::dispatch_packet_deferred(std::vector <U8> data) {
        auto packet_handler = _on_packet;
        auto message_handler = _on_message;
        auto* owner  = this;

        _ctx->post([packet_handler = std::move(packet_handler),
                    message_handler = std::move(message_handler),
                    data = std::move(data), owner]() mutable {
            PacketView packet{};
            auto rc = parse_packet(data.data(), data.size(), packet);
            if (!rc.ok()) {
                return;
            }

            if (packet_handler) {
                packet_handler(packet);
            }

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

                    owner->dispatch_message_frame(msg, message_handler);
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

        rc = pump_reliable();
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
