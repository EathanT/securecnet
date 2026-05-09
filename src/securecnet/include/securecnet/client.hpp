#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "securecnet/crypto.hpp"
#include "securecnet/congestion_control.hpp"
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

    class Client : private IoContextService {
    public:
        using OnPacketFn = std::function<void(const PacketView&)>;
        using OnMessageFn = std::function<void(const MsgView&)>;
        using OnTextFn = std::function<void(std::string_view)>;
        using OnBinaryFn = std::function<void(const MsgView&)>;
        using OnStateChangeFn = std::function<void(ConnectionState previous, ConnectionState next)>;
        using OnConnectedFn = std::function<void()>;
        using OnDisconnectedFn = std::function<void(CloseReason)>;
        using OnErrorFn = std::function<void(Result)>;
        using OnBackpressureFn = std::function<void(const BackpressureInfo&)>;
        using OnPacketDebugFn = std::function<void(std::string_view, const PacketView&)>;

        Client();
        explicit Client(const ClientConfig& config);
        explicit Client(IoContext& ctx);
        Client(const ClientConfig& config, IoContext& ctx);
        ~Client();

        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        Result start(const Endpoint& server) {
            return connect(server);
        }

        Result connect(const Endpoint& server);
        Result connect(std::string_view host, std::string_view port);
        Result connect(std::string_view host, U16 port);
        void stop();

        Result tick();

        Result send_payload(const U8* data, ST len);
        Result send_payload(std::span<const U8> payload);
        Result send_message(Channel channel, U8 type, const void* data, U16 len);
        Result send(const SendOptions& options, U8 type, std::span<const U8> payload);
        Result send(Channel channel, U8 type, std::span<const U8> payload);
        Result send_text(U8 type, std::string_view text);
        Result send_text(U8 type, std::string_view text, const SendOptions& options);
        Result send_unreliable(U8 type, std::span<const U8> payload, SendPriority priority = SendPriority::Normal);
        Result send_reliable(U8 type, std::span<const U8> payload, SendPriority priority = SendPriority::Normal, U64 lifetime_ms = 0);
        Result send_ordered(U8 type, std::span<const U8> payload, SendPriority priority = SendPriority::Normal, U64 lifetime_ms = 0);
        Result send_latest(U8 type, std::span<const U8> payload, SendPriority priority = SendPriority::Normal);

        template <class T>
        Result send_unreliable(U8 type, const T& value, SendPriority priority = SendPriority::Normal) {
            return send(SendOptions{ Channel::Unreliable, priority, 0 }, type, bytes_of(value));
        }

        template <class T>
        Result send_reliable(U8 type, const T& value, SendPriority priority = SendPriority::Normal, U64 lifetime_ms = 0) {
            return send(SendOptions{ Channel::Reliable, priority, lifetime_ms }, type, bytes_of(value));
        }

        template <class T>
        Result send_ordered(U8 type, const T& value, SendPriority priority = SendPriority::Normal, U64 lifetime_ms = 0) {
            return send(SendOptions{ Channel::ReliableOrdered, priority, lifetime_ms }, type, bytes_of(value));
        }

        template <class T>
        Result send_latest(U8 type, const T& value, SendPriority priority = SendPriority::Normal) {
            return send(SendOptions{ Channel::SequencedUnreliable, priority, 0 }, type, bytes_of(value));
        }
        Result send_unreliable_text(U8 type, std::string_view text, SendPriority priority = SendPriority::Normal);
        Result send_reliable_text(U8 type, std::string_view text, SendPriority priority = SendPriority::Normal, U64 lifetime_ms = 0);
        Result send_ordered_text(U8 type, std::string_view text, SendPriority priority = SendPriority::Normal, U64 lifetime_ms = 0);
        Result send_latest_text(U8 type, std::string_view text, SendPriority priority = SendPriority::Normal);
        Result close(CloseReason reason = CloseReason::Normal);
        Result local_endpoint(Endpoint& out) const;
        ResultT<Endpoint> local_endpoint() const;

        ConnectionState state() const { return _state; }
        CloseReason close_reason() const { return _close_reason; }
        U64 connection_id() const { return _conn_id; }
        const ClientConfig& config() const { return _config; }

        const TransportStats& stats() const { return _stats; }
        void reset_stats() { _stats.reset(); refresh_runtime_stats(); }

        void on_packet(OnPacketFn fn) { _on_packet = std::move(fn); }
        void on_message(OnMessageFn fn) { _on_message = std::move(fn); }
        void on_text(U8 type, OnTextFn fn) { _text_handlers[type] = std::move(fn); }

        template <class T, class Fn>
        void on_binary(U8 type, Fn&& fn) {
            static_assert(binary_message_type_supported_v<T>,
                          "on_binary requires a trivially copyable, default constructible non-pointer type");
            _binary_handlers[type] = [handler = std::forward<Fn>(fn)](const MsgView& msg) mutable {
                auto decoded = msg.as<T>();
                if (decoded.ok()) {
                    handler(decoded.value);
                }
            };
        }

        void on_state_change(OnStateChangeFn fn) { _on_state_change = std::move(fn); }
        void on_connected(OnConnectedFn fn) { _on_connected = std::move(fn); }
        void on_disconnected(OnDisconnectedFn fn) { _on_disconnected = std::move(fn); }
        void on_error(OnErrorFn fn) { _on_error = std::move(fn); }
        void on_backpressure(OnBackpressureFn fn) { _on_backpressure = std::move(fn); }
        void set_logger(LogFn fn) { _logger = std::move(fn); }
        void set_packet_debug_hook(OnPacketDebugFn fn) { _packet_debug = std::move(fn); }

    private:
        struct PendingPacket {
            std::array<U8, NetConfig::MaxPacketBytes> bytes{};
            ST len{ 0 };
            SendPriority priority{ SendPriority::Normal };
        };

        Result context_poll() override;
        Result runtime_status() const;
        Result reset_for_connect();
        Result enqueue_pending_packet(PendingPacket&& pending);
        Result queue_packet(PacketKind kind, bool encrypted,
            const U8* payload, ST payload_len,
            SendPriority priority,
            U64 conn_id_override = 0);
        Result queue_raw_payload(const U8* data, ST len, SendPriority priority = SendPriority::Normal);
        Result queue_internal_message(Channel channel, U8 type, const void* data, U16 len, SendPriority priority);
        Result queue_message_packet(Channel channel, U8 type, const void* data, U16 len, SendPriority priority);
        Result queue_control_ack(Channel channel, U64 message_id);
        Result queue_keepalive();
        Result queue_close_packet(CloseReason reason, bool encrypted);
        Result send_reliable_message(Channel channel, U8 type, const void* data, U16 len,
            SendPriority priority, U64 lifetime_ms);
        Result send_fragmented(const SendOptions& options, U8 type, std::span<const U8> payload);
        Result send_client_hello();
        Result flush_pending();
        Result pump_reliable();
        Result pump_receive();
        Result run_housekeeping();
        void handle_packet(const PacketView& packet);
        Result handle_handshake_packet(const PacketView& packet);
        Result handle_retry_packet(const PacketView& packet);
        Result handle_server_hello_packet(const PacketView& packet);
        Result handle_established_packet(const PacketView& packet);
        void dispatch_message_payload(const U8* payload, ST payload_len);
        void dispatch_message_frame(const MsgView& msg);
        Result handle_fragment_payload(const FragmentView& fragment);
        Result deliver_application_message(Channel channel, U8 type, const U8* data, U16 len, U64 delivery_sequence);
        Result deliver_reassembled_message(const FragmentedMessage& message);
        void emit_message(const MsgView& msg);
        void transition_state(ConnectionState next);
        void fail_connection(CloseReason reason, Errc code, const char* msg);
        void reset_session();
        void refill_send_budget(U64 now_ms);
        void refresh_runtime_stats();
        void emit_backpressure(Channel channel, U8 type, Result rc);
        void emit_log(LogLevel level, std::string_view msg) const;
        void emit_packet_debug(std::string_view direction, const PacketView& packet) const;
        static U64 now_ms();

        ClientConfig _config{};
        IoContext* _ctx{ nullptr };
        SocketInit _runtime{};
        UdpSocket _sock{};
        Endpoint _server{};

        ConnectionState _state{ ConnectionState::Idle };
        CloseReason _close_reason{ CloseReason::Normal };
        U64 _conn_id{ 0 };
        U64 _seq{ 1 };
        U64 _handshake_started_ms{ 0 };
        U64 _last_recv_ms{ 0 };
        U64 _last_send_ms{ 0 };
        U64 _send_budget_bytes{ 0 };
        U64 _last_budget_refill_ms{ 0 };
        CongestionController _congestion{};
        ST _pending_bytes{ 0 };
        U64 _next_fragment_message_id{ 1 };
        U64 _next_ordered_sequence{ 1 };
        U64 _next_sequenced_sequence{ 1 };

        KeyPair _ephemeral{};
        SessionKeys _session_keys{};
        std::array<U8, NetConfig::ClientNonceBytes> _client_nonce{};
        std::array<U8, NetConfig::ServerNonceBytes> _server_nonce{};
        RetryToken _retry_token{};
        bool _have_retry_token{ false };
        ResumptionToken _resumption_token{};
        bool _have_resumption_token{ false };
        bool _attempted_resumption_this_connect{ false };
        ReplayWindow _packet_window{};

        OnPacketFn _on_packet{};
        OnMessageFn _on_message{};
        std::unordered_map<U8, OnTextFn> _text_handlers{};
        std::unordered_map<U8, OnBinaryFn> _binary_handlers{};
        OnStateChangeFn _on_state_change{};
        OnConnectedFn _on_connected{};
        OnDisconnectedFn _on_disconnected{};
        OnErrorFn _on_error{};
        OnBackpressureFn _on_backpressure{};
        LogFn _logger{};
        OnPacketDebugFn _packet_debug{};
        std::array<U8, NetConfig::MaxPacketBytes> _rxbuf{};
        std::deque<PendingPacket> _pending{};
        ReliableSession _reliable{};
        ReliableSession _ordered_reliable{};
        OrderedReceiveWindow _ordered{};
        SequencedReceiveWindow _sequenced{};
        FragmentReassembler _reassembler{};
        TransportStats _stats{};
    };

}
