#include "securecnet/server.hpp"

#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"

#include <chrono>
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
                const auto* sa = reinterpret_cast<const sockaddr*>(&ep.addr);
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
            return Result::fail(Errc::InvalidArg, "text payload too large");
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

    U64 Server::now_ms() {
        return static_cast<U64>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
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
        _peers.clear();
        _stats.reset();
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
        _peers.clear();
        _sock.close();
    }

    Server::PeerTransportState& Server::ensure_peer_state(const Endpoint& from, U64 conn_id) {
        auto& state = _peers[from.to_string()];
        state.endpoint = from;
        if (conn_id != 0) {
            state.conn_id = conn_id;
        }
        return state;
    }

    Result Server::queue_payload(const Endpoint& to, U64 conn_id, const U8* data, ST len) {
        if (len > NetConfig::MaxPayloadBytes) {
            return Result::fail(Errc::InvalidArg, "payload too large");
        }
        if (_pending.size() >= NetConfig::MaxPendingPackets) {
            ++_stats.queue_full_events;
            return Result::fail(Errc::QueueFull, "pending packet queue full");
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

    Result Server::queue_message_frame(const Endpoint& to, U64 conn_id, Channel channel, U8 type, const void* data, U16 len) {
        std::array<U8, NetConfig::MaxPayloadBytes> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_message(writer, channel, type, data, len);
        if (!rc.ok()) {
            return rc;
        }

        rc =  queue_payload(to, conn_id, payload.data(), writer.off);
        if (!rc.ok()) {
            return rc;
        }

        ++_stats.message_frames_sent;
        return Result::success();
    }

    Result Server::queue_control_ack(const Endpoint& to, U64 conn_id, U64 message_id) {
        U8 ack_buf[sizeof(U64)]{};
        ByteWriter writer{ ack_buf, sizeof(ack_buf) };
        auto rc = write_reliable_ack(writer, message_id);
        if (!rc.ok()) {
            return rc;
        }

        rc =  queue_message_frame(to, conn_id, Channel::Control,
                                   static_cast<U8>(ControlType::ReliableAck),
                                   ack_buf, static_cast<U16>(writer.off));
        if (!rc.ok()) {
            return rc;
        }
        
        ++_stats.reliable_acks_sent;
        return Result::success();
    }

Result Server::send_reliable_message(PeerTransportState& state, U8 type, const void* data, U16 len) {
    PendingReliableMessage pending{};
    auto rc = state.reliable.enqueue(type, data, len, pending);
    if (!rc.ok()) {
        if (rc.code == Errc::QueueFull) {
            ++_stats.queue_full_events;
        }
        return rc;
    }

    ++_stats.reliable_message_enqueued; 

    const U64 conn_id = (state.conn_id != 0) ? state.conn_id : 1;
    rc = queue_message_frame(state.endpoint, conn_id, Channel::Reliable, type,
        pending.encoded_payload.data(), static_cast<U16>(pending.encoded_payload.size()));

    if (!rc.ok()) {
        state.reliable.acknowledge(pending.message_id);
        return rc;
    }

    state.reliable.note_sent(pending.message_id, now_ms());
    return Result::success();
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
    auto& state = ensure_peer_state(peer.endpoint(), peer.conn_id());
    if (channel == Channel::Reliable) {
        return send_reliable_message(state, type, data, len);
    }

    const U64 conn_id = (state.conn_id != 0) ? state.conn_id : 1;
    return queue_message_frame(state.endpoint, conn_id, channel, type, data, len);
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
                ++_stats.would_block_events;
                return Result::success();
            }
            ++_stats.socket_errors;
            return rc;
        }

        ++_stats.packets_sent;
        _stats.bytes_sent += static_cast<U64>(pending.len);
        _pending.pop_front();
    }

    return Result::success();
}


Result Server::pump_reliable() {
    for (auto& [key, state] : _peers) {
        (void)key;
        auto rc = state.reliable.resend_due(now_ms(), NetConfig::ReliableResendDelayMs,
            [this, &state](PendingReliableMessage& pending) {
                const U64 conn_id = (state.conn_id != 0) ? state.conn_id : 1;
                auto resend_rc =  queue_message_frame(state.endpoint, conn_id, Channel::Reliable, pending.user_type,
                    pending.encoded_payload.data(),
                    static_cast<U16>(pending.encoded_payload.size()));
                if (resend_rc.ok()) {
                    ++_stats.reliable_retransmits;
                }
                return resend_rc;
            });
        if (!rc.ok()) {
            return rc;
        }
    }

    return Result::success();
}

void Server::dispatch_message_frame(PeerTransportState& state, const Endpoint& from, U64 packet_conn_id,
    const MsgView& msg, const OnMessageFn& message_handler) {
    const U64 conn_id = (state.conn_id != 0) ? state.conn_id : packet_conn_id;

    if (msg.channel == Channel::Control && msg.type == static_cast<U8>(ControlType::ReliableAck)) {
        ByteReader ack_reader{ msg.data, static_cast<ST>(msg.len) };
        U64 acked_message_id = 0;
        auto rc = read_reliable_ack(ack_reader, acked_message_id);
        if (rc.ok()) {
            state.reliable.acknowledge(acked_message_id);
            ++_stats.reliable_acks_received;
        }
        else {
            ++_stats.bad_packets;
        }
        return;
    }

    if (msg.channel == Channel::Reliable) {
        ByteReader reliable_reader{ msg.data, static_cast<ST>(msg.len) };
        ReliablePayloadView reliable{};
        auto rc = read_reliable_payload(reliable_reader, reliable);
        if (!rc.ok()) {
            ++_stats.bad_packets;
            return;
        }

        (void)queue_control_ack(from, conn_id, reliable.message_id);
        if (!state.reliable.accept_incoming(reliable.message_id)) {
            return;
        }

        ++_stats.reliable_messages_delivered;
        if (message_handler) {
            Peer peer{ this, from, conn_id };
            MsgView delivered{};
            delivered.channel = Channel::Reliable;
            delivered.type = msg.type;
            delivered.data = reliable.data;
            delivered.len = reliable.len;
            message_handler(peer, delivered);
        }
        return;
    }

    if (message_handler) {
        Peer peer{ this, from, conn_id };
        message_handler(peer, msg);
    }
}

    void Server::dispatch_packet_inline(const Endpoint& from, const U8* data, ST len) {
        PacketView packet{};
        auto rc = parse_packet(data, len, packet);
        if (!rc.ok()) {
            ++_stats.bad_packets;
            return;
        }
    
        auto& state = ensure_peer_state(from, packet.h.conn_id);

        if (_on_packet) {
            _on_packet(from, packet);
        }

        ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
        for (;;) {
            MsgView msg{};
            auto msg_rc = read_message(reader, msg);
            if (msg_rc.code == Errc::EndOfStream) {
                break;
            }
            if (!msg_rc.ok()) {
                ++_stats.bad_packets;
                break; 
            }
            
            ++_stats.message_frames_received;
            dispatch_message_frame(state, from, packet.h.conn_id, msg, _on_message);
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
                ++owner->_stats.bad_packets;
                return; 
            }

            auto& state = owner->ensure_peer_state(from, packet.h.conn_id);

            if (packet_handler) {
                packet_handler(from, packet);
            }

                ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
                for (;;) {
                    MsgView msg{};
                    auto msg_rc = read_message(reader, msg);
                    if (msg_rc.code == Errc::EndOfStream) {
                        break;
                    }
                    if (!msg_rc.ok()) {
                        ++owner->_stats.bad_packets;
                        break;
                    }

                    ++owner->_stats.message_frames_received;
                    owner->dispatch_message_frame(state, from, packet.h.conn_id, msg, message_handler);
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
                    ++_stats.would_block_events;
                    break;
                }
                if (rc.code == Errc::Truncated) {
                    ++_stats.truncated_datagrams;
                    continue;
                }

                ++_stats.socket_errors;
                return rc;
            }

            ++_stats.packets_received;
            _stats.bytes_received += static_cast<U64>(n);

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

        rc = pump_reliable();
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
