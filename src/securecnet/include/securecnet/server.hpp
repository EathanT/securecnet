#pragma once
#include "securecnet/io_context.hpp"
#include "securecnet/message.hpp"
#include "securecnet/result.hpp"
#include "securecnet/udp_socket.hpp"
#include "securecnet/packet.hpp"
#include "securecnet/socket_init.hpp"
#include "securecnet/reliability.hpp"
#include "securecnet/transport_stats.hpp"

#include <array>
#include <deque>
#include <functional>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>
#include <unordered_map>

namespace scn {

    class Server final : private IoContextService {
    public:
        class Peer {
        public:
            Peer() = default;
            Peer(Server* owner, Endpoint endpoint, U64 conn_id)
                : _owner(owner), _endpoint(std::move(endpoint)), _conn_id(conn_id) {}

            const Endpoint& endpoint() const { return _endpoint; }
            U64 conn_id() const { return _conn_id; }

            Result send_payload(const U8* data, ST len) const;
            Result send_payload(std::span<const U8> payload) const;
            Result send_message(Channel channel, U8 type, const void* data, U16 len) const;
            Result send(Channel channel, U8 type, std::span<const U8> payload) const;
            Result send_text(U8 type, std::string_view text) const;

        private:
            Server* _owner{ nullptr };
            Endpoint _endpoint{};
            U64 _conn_id{ 0 };
        };

        using OnPacketFn = std::function<void(const Endpoint& from, const PacketView&)>;
        using OnMessageFn = std::function<void(Peer peer, const MsgView&)>;

        Server() = default;
        explicit Server(IoContext& ctx);
        ~Server();

        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;

        Result start(const Endpoint& bind_ep) {
            return listen(bind_ep);
        }

        Result listen(const Endpoint& bind_ep);
        Result listen(std::string_view port);
        Result listen(U16 port);
        void stop();

        Result tick();

        Result send_payload(const Endpoint& to, U64 conn_id, const U8* data, ST len);
        Result send_payload(const Peer& peer, const U8* data, ST len);
        Result send_payload(const Peer& peer, std::span<const U8> payload);
        Result send_message(const Peer& peer, Channel channel, U8 type, const void* data, U16 len);
        Result send(const Peer& peer, Channel channel, U8 type, std::span<const U8> payload);
        Result send_text(const Peer& peer, U8 type, std::string_view text);
        Result local_endpoint(Endpoint& out) const;

        const TransportStats& stats() const { return _stats; }
        void reset_stats() { _stats.reset(); }
        ST peer_count() const { return _peers.size();  }

        void on_packet(OnPacketFn fn) { _on_packet = std::move(fn); }
        void on_message(OnMessageFn fn) { _on_message = std::move(fn); }

    private:
        struct PendingPacket {
            Endpoint to{};
            std::array<U8, NetConfig::MaxPacketBytes> bytes{};
            ST len{ 0 };
        };

        struct PeerTransportState {
            Endpoint endpoint{};
            U64 conn_id{ 0 };
            ReliableSession reliable{};
        };

        Result context_poll() override;
        Result runtime_status() const;
        Result queue_payload(const Endpoint& to, U64 conn_id, const U8* data, ST len);
        Result queue_message_frame(const Endpoint& to, U64 conn_id, Channel channel, U8 type, const void* data, U16 len);
        Result queue_control_ack(const Endpoint& to, U64 conn_id, U64 message_id);
        Result send_reliable_message(PeerTransportState& state, U8 type, const void* data, U16 len);
        Result flush_pending();
        Result pump_reliable();
        Result pump_receive();

        PeerTransportState& ensure_peer_state(const Endpoint& from, U64 conn_id);
        void dispatch_message_frame(PeerTransportState& state, const Endpoint& from, U64 packet_conn_id,
                                    const MsgView& msg, const OnMessageFn& message_handler); 
        void dispatch_packet_inline(const Endpoint& from, const U8* data, ST len);
        void dispatch_packet_deferred(Endpoint from, std::vector<U8> data);
        static U64 now_ms();

        IoContext* _ctx{ nullptr };
        SocketInit _runtime{};
        UdpSocket _sock{};
        U64 _seq{ 1 };

        OnPacketFn _on_packet{};
        OnMessageFn _on_message{};
        U8 _rxbuf[NetConfig::MaxPacketBytes]{};
        std::deque<PendingPacket> _pending{};
        std::unordered_map<std::string, PeerTransportState> _peers{};
        TransportStats _stats{};
    };

}
