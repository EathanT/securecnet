#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <span>
#include <string_view>
#include <unordered_map>

#include "securecnet/crypto.hpp"
#include "securecnet/fragmentation.hpp"
#include "securecnet/io_context.hpp"
#include "securecnet/logging.hpp"
#include "securecnet/message.hpp"
#include "securecnet/packet.hpp"
#include "securecnet/protocol.hpp"
#include "securecnet/reliability.hpp"
#include "securecnet/result.hpp"
#include "securecnet/socket_init.hpp"
#include "securecnet/transport_stats.hpp"
#include "securecnet/udp_socket.hpp"

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
            Result send(const SendOptions& options, U8 type, std::span<const U8> payload) const;
            Result send(Channel channel, U8 type, std::span<const U8> payload) const;
            Result send_text(U8 type, std::string_view text) const;
            Result close(CloseReason reason = CloseReason::Normal) const;

        private:
            Server* _owner{ nullptr };
            Endpoint _endpoint{};
            U64 _conn_id{ 0 };
        };

        using OnPacketFn = std::function<void(const Endpoint& from, const PacketView&)>;
        using OnMessageFn = std::function<void(Peer peer, const MsgView&)>;
        using OnPacketDebugFn = std::function<void(std::string_view, const Endpoint&, const PacketView&)>;

        Server();
        explicit Server(const ServerConfig& config);
        explicit Server(IoContext& ctx);
        Server(const ServerConfig& config, IoContext& ctx);
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
        Result send(const Peer& peer, const SendOptions& options, U8 type, std::span<const U8> payload);
        Result send(const Peer& peer, Channel channel, U8 type, std::span<const U8> payload);
        Result send_text(const Peer& peer, U8 type, std::string_view text);
        Result close_peer(const Peer& peer, CloseReason reason = CloseReason::Normal);
        Result local_endpoint(Endpoint& out) const;

        const TransportStats& stats() const { return _stats; }
        void reset_stats() { _stats.reset(); refresh_runtime_stats(); }
        ST peer_count() const { return _sessions.size(); }
        const ServerConfig& config() const { return _config; }

        void on_packet(OnPacketFn fn) { _on_packet = std::move(fn); }
        void on_message(OnMessageFn fn) { _on_message = std::move(fn); }
        void set_logger(LogFn fn) { _logger = std::move(fn); }
        void set_packet_debug_hook(OnPacketDebugFn fn) { _packet_debug = std::move(fn); }

    private:
        struct PendingPacket {
            Endpoint to{};
            U64 owner_conn_id{ 0 };
            std::array<U8, NetConfig::MaxPacketBytes> bytes{};
            ST len{ 0 };
            SendPriority priority{ SendPriority::Normal };
        };

        struct PeerSession {
            Endpoint endpoint{};
            U64 conn_id{ 0 };
            ConnectionState state{ ConnectionState::Idle };
            CloseReason close_reason{ CloseReason::Normal };
            U64 created_ms{ 0 };
            U64 last_recv_ms{ 0 };
            U64 last_send_ms{ 0 };
            U64 send_seq{ 1 };
            U64 send_budget_bytes{ 0 };
            U64 last_budget_refill_ms{ 0 };
            U64 next_fragment_message_id{ 1 };
            U64 next_ordered_sequence{ 1 };
            U64 next_sequenced_sequence{ 1 };
            bool handshake_had_retry_token{ false };
            RetryToken handshake_retry_token{};
            bool handshake_had_resumption_token{ false };
            ResumptionToken handshake_resumption_token{};
            KeyPair ephemeral{};
            SessionKeys keys{};
            std::array<U8, NetConfig::ClientNonceBytes> client_nonce{};
            std::array<U8, NetConfig::ServerNonceBytes> server_nonce{};
            std::array<U8, NetConfig::KeyExchangePublicKeyBytes> client_public_key{};
            ReplayWindow packet_window{};
            ReliableSession reliable{};
            ReliableSession ordered_reliable{};
            OrderedReceiveWindow ordered{};
            SequencedReceiveWindow sequenced{};
            FragmentReassembler reassembler{};
        };

        struct IpAbuseState {
            U64 window_started_ms{ 0 };
            U32 handshakes_in_window{ 0 };
            U32 invalid_penalty_score{ 0 };
            U64 banned_until_ms{ 0 };
        };

        struct PreauthBudgetState {
            U64 bytes_received{ 0 };
            U64 bytes_sent{ 0 };
            U64 last_seen_ms{ 0 };
        };

        Result context_poll() override;
        Result runtime_status() const;
        Result enqueue_pending_packet(PendingPacket&& pending);
        Result queue_packet(const Endpoint& to, PacketKind kind, bool encrypted,
                            const U8* payload, ST payload_len,
                            U64 conn_id, U64 seq,
                            const SessionKeys* keys,
                            SendPriority priority,
                            U64 owner_conn_id);
        Result queue_plain_handshake(const Endpoint& to, const U8* payload, ST payload_len, U64 conn_id);
        Result queue_retry(const Endpoint& to, const RetryToken& token);
        Result queue_server_hello(PeerSession& session);
        Result queue_internal_message(PeerSession& session, Channel channel, U8 type, const void* data, U16 len, SendPriority priority);
        Result queue_message_packet(PeerSession& session, Channel channel, U8 type, const void* data, U16 len, SendPriority priority);
        Result queue_raw_payload(PeerSession& session, const U8* data, ST len, SendPriority priority);
        Result queue_control_ack(PeerSession& session, Channel channel, U64 message_id);
        Result queue_keepalive(PeerSession& session);
        Result queue_close_packet(const Endpoint& to, U64 conn_id, CloseReason reason, bool encrypted,
                                  const SessionKeys* keys, U64 seq, SendPriority priority, U64 owner_conn_id);
        Result send_reliable_message(PeerSession& session, Channel channel, U8 type, const void* data, U16 len,
                                     SendPriority priority, U64 lifetime_ms);
        Result send_fragmented(PeerSession& session, const SendOptions& options, U8 type, std::span<const U8> payload);
        Result flush_pending();
        Result pump_reliable();
        Result pump_receive();
        Result run_housekeeping();

        void handle_packet(const Endpoint& from, const PacketView& packet, ST wire_len);
        Result handle_handshake_packet(const Endpoint& from, const PacketView& packet, ST wire_len);
        Result handle_client_hello(const Endpoint& from, const ClientHello& hello, ST wire_len);
        Result handle_session_packet(PeerSession& session, const PacketView& packet);
        void dispatch_message_payload(PeerSession& session, const U8* payload, ST payload_len);
        void dispatch_message_frame(PeerSession& session, const MsgView& msg);
        Result handle_fragment_payload(PeerSession& session, const FragmentView& fragment);
        Result deliver_application_message(PeerSession& session, Channel channel, U8 type, const U8* data, U16 len, U64 delivery_sequence);
        Result deliver_reassembled_message(PeerSession& session, const FragmentedMessage& message);

        void transition_state(PeerSession& session, ConnectionState next);
        void close_session(PeerSession& session, CloseReason reason, bool send_close);
        void evict_session(U64 conn_id);
        void evict_stale_sessions();
        void refill_send_budget(PeerSession& session, U64 now_ms);
        void refresh_runtime_stats();
        U64 allocate_conn_id();
        PeerSession* find_session(U64 conn_id);
        const PeerSession* find_session(U64 conn_id) const;
        PeerSession* find_session_by_endpoint(const Endpoint& endpoint);
        RetryToken make_retry_token(const Endpoint& from, const ClientHello& hello, U64 issued_at_ms) const;
        Result validate_retry_token(const Endpoint& from, const ClientHello& hello, const RetryToken& token, U64 now) const;
        ResumptionToken make_resumption_token(const Endpoint& from, U64 issued_at_ms) const;
        Result validate_resumption_token(const Endpoint& from, const ResumptionToken& token, U64 now) const;
        IpAbuseState& abuse_state_for(const Endpoint& endpoint);
        PreauthBudgetState& preauth_state_for(const Endpoint& endpoint);
        bool endpoint_rate_limited(const Endpoint& endpoint, U64 now_ms);
        bool endpoint_is_banned(const Endpoint& endpoint, U64 now_ms);
        void note_invalid_packet(const Endpoint& endpoint, U64 now_ms);
        bool can_amplify_to(const Endpoint& endpoint, U64 bytes_to_send, U64 now_ms);
        void note_preauth_receive(const Endpoint& endpoint, U64 bytes_received, U64 now_ms);
        void note_preauth_send(const Endpoint& endpoint, U64 bytes_sent, U64 now_ms);
        U64 total_reassembly_memory_bytes() const;
        static std::string endpoint_host_key(const Endpoint& endpoint);
        void emit_log(LogLevel level, std::string_view msg) const;
        void emit_packet_debug(std::string_view direction, const Endpoint& endpoint, const PacketView& packet) const;
        static U64 now_ms();

        ServerConfig _config{};
        IoContext* _ctx{ nullptr };
        SocketInit _runtime{};
        UdpSocket _sock{};
        U64 _stateless_seq{ 1 };
        ST _pending_bytes{ 0 };

        OnPacketFn _on_packet{};
        OnMessageFn _on_message{};
        LogFn _logger{};
        OnPacketDebugFn _packet_debug{};
        std::array<U8, NetConfig::MaxPacketBytes> _rxbuf{};
        std::deque<PendingPacket> _pending{};
        std::unordered_map<U64, PeerSession> _sessions{};
        std::unordered_map<std::string, U64> _endpoint_to_conn{};
        std::unordered_map<std::string, IpAbuseState> _ip_abuse{};
        std::unordered_map<std::string, PreauthBudgetState> _preauth{};
        std::array<U8, NetConfig::CookieSecretBytes> _cookie_secret{};
        TransportStats _stats{};
    };

} // namespace scn
