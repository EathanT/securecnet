#include "securecnet/client.hpp"

#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"

#include <algorithm>
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
            } else if (sa->sa_family == AF_INET6) {
                reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr = in6addr_loopback;
            }
            return normalized;
        }

        Result build_transcript_mac_input(const ClientHello& hello,
                                          const ServerHello& server_hello,
                                          U8* out, ST out_cap, ST& out_len) {
            out_len = 0;
            ByteWriter writer{ out, out_cap };
            Result rc = writer.write_u16(NetConfig::ProtocolVersion);
            if (!rc.ok()) return rc;
            rc = writer.write_bytes(hello.client_public_key.data(), hello.client_public_key.size());
            if (!rc.ok()) return rc;
            rc = writer.write_bytes(hello.client_nonce.data(), hello.client_nonce.size());
            if (!rc.ok()) return rc;
            rc = writer.write_u8(hello.has_retry_token ? 1 : 0);
            if (!rc.ok()) return rc;
            if (hello.has_retry_token) {
                rc = write_retry_token(writer, hello.retry_token);
                if (!rc.ok()) return rc;
            }
            rc = writer.write_u8(hello.has_resumption_token ? 1 : 0);
            if (!rc.ok()) return rc;
            if (hello.has_resumption_token) {
                rc = write_resumption_token(writer, hello.resumption_token);
                if (!rc.ok()) return rc;
            }
            rc = writer.write_u64(server_hello.server_conn_id);
            if (!rc.ok()) return rc;
            rc = writer.write_bytes(server_hello.server_public_key.data(), server_hello.server_public_key.size());
            if (!rc.ok()) return rc;
            rc = writer.write_bytes(server_hello.server_nonce.data(), server_hello.server_nonce.size());
            if (!rc.ok()) return rc;
            rc = writer.write_u8(server_hello.has_resumption_token ? 1 : 0);
            if (!rc.ok()) return rc;
            if (server_hello.has_resumption_token) {
                rc = write_resumption_token(writer, server_hello.resumption_token);
                if (!rc.ok()) return rc;
            }
            out_len = writer.off;
            return Result::success();
        }

    } // namespace

    Client::Client() {
        _reliable.configure(_config.reliability);
        _ordered_reliable.configure(_config.reliability);
        _ordered.set_max_buffered(_config.reliability.ordered_receive_window);
        _reassembler.configure(_config.fragmentation);
        _send_budget_bytes = _config.send_budget_bytes_per_second;
        _last_budget_refill_ms = now_ms();
        refresh_runtime_stats();
    }

    Client::Client(const ClientConfig& config) : _config(config) {
        _reliable.configure(_config.reliability);
        _ordered_reliable.configure(_config.reliability);
        _ordered.set_max_buffered(_config.reliability.ordered_receive_window);
        _reassembler.configure(_config.fragmentation);
        _send_budget_bytes = _config.send_budget_bytes_per_second;
        _last_budget_refill_ms = now_ms();
        refresh_runtime_stats();
    }

    Client::Client(IoContext& ctx) : Client() {
        _ctx = &ctx;
        _ctx->register_service(this);
    }

    Client::Client(const ClientConfig& config, IoContext& ctx) : Client(config) {
        _ctx = &ctx;
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

    void Client::emit_log(LogLevel level, std::string_view msg) const {
        if (_logger) {
            _logger(level, msg);
        }
    }

    void Client::emit_packet_debug(std::string_view direction, const PacketView& packet) const {
        if (_config.enable_packet_debug_dumps && _packet_debug) {
            _packet_debug(direction, packet);
        }
    }

    Result Client::runtime_status() const {
        auto rc = _ctx ? _ctx->runtime_status() : _runtime.status();
        if (!rc.ok()) {
            return rc;
        }
        return crypto_runtime_status();
    }

    void Client::transition_state(ConnectionState next) {
        if (_state == next) {
            return;
        }
        _state = next;
        ++_stats.state_transitions;
        refresh_runtime_stats();
        emit_log(LogLevel::Trace, "client state transition");
    }

    void Client::refresh_runtime_stats() {
        _stats.current_peer_count = (_state == ConnectionState::Idle || _state == ConnectionState::Closed) ? 0 : 1;
        _stats.current_pending_packets = _pending.size();
        _stats.current_reliable_pending = _reliable.pending_count() + _ordered_reliable.pending_count();
        _stats.current_reliable_inflight = _reliable.inflight_count() + _ordered_reliable.inflight_count();
        _stats.current_reassembly_count = _reassembler.active_count();
        _stats.current_reassembly_memory_bytes = _reassembler.memory_bytes();
        _stats.current_send_budget_bytes = _send_budget_bytes;

        const U64 primary_latest = std::max(_reliable.latest_rtt_ms(), _ordered_reliable.latest_rtt_ms());
        const U64 primary_srtt = std::max(_reliable.smoothed_rtt_ms(), _ordered_reliable.smoothed_rtt_ms());
        const U64 primary_rttvar = std::max(_reliable.rtt_variance_ms(), _ordered_reliable.rtt_variance_ms());
        const U64 primary_rto = std::max(_reliable.rto_ms(), _ordered_reliable.rto_ms());
        _stats.rtt_latest_ms = primary_latest;
        _stats.rtt_smoothed_ms = primary_srtt;
        _stats.rtt_variance_ms = primary_rttvar;
        _stats.current_retransmit_timeout_ms = primary_rto;
        _stats.estimated_loss_per_mille = std::max(_reliable.loss_per_mille(), _ordered_reliable.loss_per_mille());
    }

    void Client::reset_session() {
        _conn_id = 0;
        _seq = 1;
        _handshake_started_ms = 0;
        _last_recv_ms = 0;
        _last_send_ms = 0;
        _pending_bytes = 0;
        _send_budget_bytes = _config.send_budget_bytes_per_second;
        _last_budget_refill_ms = now_ms();
        _next_fragment_message_id = 1;
        _next_ordered_sequence = 1;
        _next_sequenced_sequence = 1;
        _attempted_resumption_this_connect = false;
        _have_retry_token = false;
        _retry_token = {};
        _client_nonce.fill(0);
        _server_nonce.fill(0);
        _packet_window.reset();
        _pending.clear();
        _reliable.configure(_config.reliability);
        _ordered_reliable.configure(_config.reliability);
        _reliable.clear();
        _ordered_reliable.clear();
        _ordered.set_max_buffered(_config.reliability.ordered_receive_window);
        _ordered.clear();
        _sequenced.clear();
        _reassembler.configure(_config.fragmentation);
        _reassembler.clear();
        _session_keys.clear();
        _ephemeral.clear();
        refresh_runtime_stats();
    }

    void Client::fail_connection(CloseReason reason, Errc, const char* msg) {
        if (_state == ConnectionState::Handshaking) {
            ++_stats.handshake_failures;
        }
        emit_log(LogLevel::Error, msg ? std::string_view(msg) : std::string_view{});
        _close_reason = reason;
        _pending.clear();
        _pending_bytes = 0;
        _reliable.clear();
        _ordered_reliable.clear();
        _ordered.clear();
        _sequenced.clear();
        _reassembler.clear();
        _session_keys.clear();
        _ephemeral.clear();
        _packet_window.reset();
        _sock.close();
        transition_state(ConnectionState::Closed);
        refresh_runtime_stats();
    }

    Result Client::reset_for_connect() {
        auto rc = validate_client_config(_config);
        if (!rc.ok()) {
            return rc;
        }
        stop();
        reset_session();
        _close_reason = CloseReason::Normal;
        transition_state(ConnectionState::Idle);
        return Result::success();
    }

    Result Client::connect(const Endpoint& server) {
        auto rc = runtime_status();
        if (!rc.ok()) {
            return rc;
        }
        rc = reset_for_connect();
        if (!rc.ok()) {
            return rc;
        }

        _server = normalize_connect_endpoint(server);
        const int family = reinterpret_cast<const sockaddr*>(&_server.addr)->sa_family;
        rc = _sock.open(family);
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

        rc = crypto_generate_keypair(_ephemeral);
        if (!rc.ok()) {
            _sock.close();
            return rc;
        }
        crypto_random_bytes(_client_nonce.data(), _client_nonce.size());

        _stats.reset();
        _stats.handshake_attempts = 1;
        _attempted_resumption_this_connect = _config.enable_session_resumption && _have_resumption_token;
        if (_attempted_resumption_this_connect) {
            ++_stats.session_resumptions_attempted;
        }
        _handshake_started_ms = now_ms();
        transition_state(ConnectionState::Handshaking);
        refresh_runtime_stats();
        emit_log(LogLevel::Info, "client starting handshake");
        return send_client_hello();
    }

    Result Client::connect(std::string_view host, std::string_view port) {
        std::vector<Endpoint> eps;
        auto rc = resolve_endpoints(host, port, false, eps);
        if (!rc.ok()) {
            return rc;
        }
        const Endpoint* server = prefer_ipv4(eps);
        if (!server) {
            return Result::fail(Errc::ResolveError, "no endpoints returned");
        }
        return connect(*server);
    }

    Result Client::connect(std::string_view host, U16 port) {
        return connect(host, std::to_string(port));
    }

    void Client::stop() {
        _sock.close();
        reset_session();
        transition_state(ConnectionState::Idle);
        _close_reason = CloseReason::Normal;
        refresh_runtime_stats();
    }

    Result Client::enqueue_pending_packet(PendingPacket&& pending) {
        if (_pending.size() >= _config.max_pending_packets) {
            ++_stats.queue_full_events;
            return Result::fail(Errc::QueueFull, "pending packet queue full");
        }
        auto insert_pos = _pending.end();
        for (auto it = _pending.begin(); it != _pending.end(); ++it) {
            if (static_cast<U8>(it->priority) < static_cast<U8>(pending.priority)) {
                insert_pos = it;
                break;
            }
        }
        _pending_bytes += pending.len;
        _pending.insert(insert_pos, std::move(pending));
        refresh_runtime_stats();
        return Result::success();
    }

    Result Client::queue_packet(PacketKind kind, bool encrypted,
                                const U8* payload, ST payload_len,
                                SendPriority priority,
                                U64 conn_id_override) {
        if (payload_len > 0 && !payload) {
            return Result::fail(Errc::InvalidArg, "payload is null");
        }
        if (encrypted && payload_len > NetConfig::MaxEncryptedPlaintextBytes) {
            return Result::fail(Errc::InvalidArg, "encrypted payload too large");
        }
        if (!encrypted && payload_len > NetConfig::MaxPayloadBytes) {
            return Result::fail(Errc::InvalidArg, "payload too large");
        }

        PacketHeader header{};
        header.kind = static_cast<U8>(kind);
        header.flags = encrypted ? PacketFlagEncrypted : 0;
        header.conn_id = (conn_id_override != 0) ? conn_id_override : _conn_id;
        header.seq = _seq++;

        std::array<U8, NetConfig::MaxPayloadBytes> packet_payload{};
        ST packet_payload_len = payload_len;
        if (encrypted) {
            if (_session_keys.empty() || header.conn_id == 0) {
                return Result::fail(Errc::StateError, "session keys not ready");
            }
            header.payload_len = static_cast<U32>(payload_len + NetConfig::AeadTagBytes);

            std::array<U8, NetConfig::PacketHeaderBytes> aad{};
            ByteWriter aad_writer{ aad.data(), aad.size() };
            auto rc = write_packet_header(aad_writer, header);
            if (!rc.ok()) {
                return rc;
            }

            std::array<U8, NetConfig::AeadNonceBytes> nonce{};
            crypto_make_packet_nonce(header.conn_id, header.seq, nonce);
            rc = crypto_aead_encrypt(_session_keys.tx.data(), _session_keys.tx.size(),
                                     nonce.data(), nonce.size(),
                                     aad.data(), aad_writer.off,
                                     payload, payload_len,
                                     packet_payload.data(), packet_payload.size(), packet_payload_len);
            if (!rc.ok()) {
                return rc;
            }
        } else {
            header.payload_len = static_cast<U32>(payload_len);
            if (payload_len > 0) {
                std::memcpy(packet_payload.data(), payload, payload_len);
            }
        }

        PendingPacket pending{};
        pending.priority = priority;
        auto rc = pack_packet(header,
                              packet_payload_len == 0 ? nullptr : packet_payload.data(),
                              packet_payload_len,
                              pending.bytes.data(), pending.bytes.size(), pending.len);
        if (!rc.ok()) {
            return rc;
        }
        return enqueue_pending_packet(std::move(pending));
    }

    void Client::refill_send_budget(U64 now) {
        if (_last_budget_refill_ms == 0) {
            _last_budget_refill_ms = now;
            if (_send_budget_bytes == 0) {
                _send_budget_bytes = _config.send_budget_bytes_per_second;
            }
            return;
        }
        if (now <= _last_budget_refill_ms) {
            return;
        }
        const U64 elapsed_ms = now - _last_budget_refill_ms;
        const U64 refill = (static_cast<U64>(_config.send_budget_bytes_per_second) * elapsed_ms) / 1000;
        if (refill > 0) {
            const U64 max_bucket = static_cast<U64>(_config.send_budget_bytes_per_second) * 2;
            _send_budget_bytes = std::min<U64>(max_bucket, _send_budget_bytes + refill);
            _last_budget_refill_ms = now;
            ++_stats.send_budget_refills;
            refresh_runtime_stats();
        }
    }

    Result Client::queue_raw_payload(const U8* data, ST len, SendPriority priority) {
        return queue_packet(PacketKind::Raw, true, data, len, priority);
    }

    Result Client::queue_internal_message(Channel channel, U8 type, const void* data, U16 len, SendPriority priority) {
        std::array<U8, NetConfig::MaxEncryptedPlaintextBytes> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_message(writer, channel, type, data, len);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_packet(PacketKind::Message, true, payload.data(), writer.off, priority);
        if (!rc.ok()) {
            return rc;
        }
        ++_stats.message_frames_sent;
        return Result::success();
    }

    Result Client::queue_message_packet(Channel channel, U8 type, const void* data, U16 len, SendPriority priority) {
        if (channel == Channel::Control) {
            return Result::fail(Errc::StateError, "control channel is reserved");
        }
        return queue_internal_message(channel, type, data, len, priority);
    }

    Result Client::queue_control_ack(Channel channel, U64 message_id) {
        std::array<U8, 16> ack_buf{};
        ByteWriter ack_writer{ ack_buf.data(), ack_buf.size() };
        auto rc = write_reliable_ack(ack_writer, channel, message_id);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_internal_message(Channel::Control,
                                    static_cast<U8>(ControlType::ReliableAck),
                                    ack_buf.data(), static_cast<U16>(ack_writer.off),
                                    SendPriority::High);
        if (!rc.ok()) {
            return rc;
        }
        ++_stats.reliable_acks_sent;
        return Result::success();
    }

    Result Client::queue_keepalive() {
        auto rc = queue_packet(PacketKind::Keepalive, true, nullptr, 0, SendPriority::High);
        if (rc.ok()) {
            ++_stats.keepalives_sent;
        }
        return rc;
    }

    Result Client::queue_close_packet(CloseReason reason, bool encrypted) {
        std::array<U8, 8> buf{};
        ByteWriter writer{ buf.data(), buf.size() };
        CloseFrame close_frame{};
        close_frame.reason = reason;
        auto rc = write_close_frame(writer, close_frame);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_packet(PacketKind::Close, encrypted, buf.data(), writer.off, SendPriority::High);
        if (rc.ok()) {
            ++_stats.closes_sent;
        }
        return rc;
    }

    Result Client::send_reliable_message(Channel channel, U8 type, const void* data, U16 len,
                                         SendPriority priority, U64 lifetime_ms) {
        const U16 max_len = static_cast<U16>(NetConfig::MaxReliableMessageBytes);
        if (len > max_len) {
            return Result::fail(Errc::TooLarge, "reliable payload exceeds inline channel budget");
        }

        ReliableSession& session = (channel == Channel::ReliableOrdered) ? _ordered_reliable : _reliable;
        PendingReliableMessage pending{};
        auto rc = session.enqueue(type, data, len, priority, lifetime_ms, now_ms(), pending);
        if (!rc.ok()) {
            if (rc.code == Errc::QueueFull) {
                ++_stats.queue_full_events;
            }
            return rc;
        }

        ++_stats.reliable_message_enqueued;
        rc = queue_message_packet(channel, type,
                                  pending.encoded_payload.data(),
                                  static_cast<U16>(pending.encoded_payload.size()),
                                  priority);
        if (!rc.ok()) {
            (void)session.acknowledge(pending.message_id, now_ms());
            if (rc.code == Errc::QueueFull) {
                ++_stats.backpressure_events;
            }
            return rc;
        }

        (void)session.note_sent(pending.message_id, now_ms());
        refresh_runtime_stats();
        return Result::success();
    }

    Result Client::send_fragmented(const SendOptions& options, U8 type, std::span<const U8> payload) {
        if (!_config.fragmentation.enabled) {
            return Result::fail(Errc::TooLarge, "fragmentation disabled");
        }
        if (!channel_is_application(options.channel)) {
            return Result::fail(Errc::InvalidArg, "fragment channel must be an application channel");
        }
        if (payload.size() > _config.fragmentation.max_reassembled_message_bytes) {
            return Result::fail(Errc::TooLarge, "payload exceeds reassembly policy");
        }

        const U16 original_length = static_cast<U16>(payload.size());
        const U16 fragment_count = fragment_count_for_length(original_length);
        if (fragment_count == 0 || fragment_count > _config.fragmentation.max_fragments_per_message) {
            return Result::fail(Errc::TooLarge, "fragment count exceeds policy");
        }

        const U64 logical_message_id = _next_fragment_message_id++;
        U64 delivery_sequence = 0;
        if (options.channel == Channel::ReliableOrdered) {
            delivery_sequence = _next_ordered_sequence++;
        } else if (options.channel == Channel::SequencedUnreliable) {
            delivery_sequence = _next_sequenced_sequence++;
        }

        for (U16 fragment_index = 0; fragment_index < fragment_count; ++fragment_index) {
            const U16 fragment_len = fragment_size_for_index(original_length, fragment_index);
            const ST offset = static_cast<ST>(fragment_index) * NetConfig::MaxFragmentDataBytes;

            std::array<U8, NetConfig::MaxMessageBytes> encoded{};
            ByteWriter writer{ encoded.data(), encoded.size() };
            auto rc = write_fragment_payload(writer,
                                             logical_message_id,
                                             delivery_sequence,
                                             options.channel,
                                             type,
                                             fragment_index,
                                             fragment_count,
                                             original_length,
                                             payload.data() + offset,
                                             fragment_len);
            if (!rc.ok()) {
                return rc;
            }

            if (channel_is_reliable(options.channel)) {
                rc = send_reliable_message(options.channel,
                                           static_cast<U8>(ControlType::Fragment),
                                           encoded.data(), static_cast<U16>(writer.off),
                                           options.priority,
                                           options.lifetime_ms);
            } else {
                rc = queue_internal_message(Channel::Control,
                                            static_cast<U8>(ControlType::Fragment),
                                            encoded.data(), static_cast<U16>(writer.off),
                                            options.priority);
            }
            if (!rc.ok()) {
                return rc;
            }
            ++_stats.fragments_sent;
        }

        ++_stats.fragmented_messages_sent;
        refresh_runtime_stats();
        return Result::success();
    }

    Result Client::send_payload(const U8* data, ST len) {
        if (_state != ConnectionState::Established) {
            return Result::fail(Errc::StateError, "connection not established");
        }
        if (len > NetConfig::MaxEncryptedPlaintextBytes) {
            return Result::fail(Errc::TooLarge, "raw payload too large");
        }
        return queue_raw_payload(data, len, SendPriority::Normal);
    }

    Result Client::send_payload(std::span<const U8> payload) {
        return send_payload(payload.data(), payload.size());
    }

    Result Client::send_message(Channel channel, U8 type, const void* data, U16 len) {
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "message data is null");
        }
        return send({ channel, SendPriority::Normal, 0 }, type,
                    std::span<const U8>(static_cast<const U8*>(data), len));
    }

    Result Client::send(const SendOptions& options, U8 type, std::span<const U8> payload) {
        if (_state != ConnectionState::Established) {
            return Result::fail(Errc::StateError, "connection not established");
        }
        if (!channel_is_application(options.channel)) {
            return Result::fail(Errc::InvalidArg, "send channel must be an application channel");
        }
        if (payload.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::TooLarge, "message payload too large");
        }

        const U16 len = static_cast<U16>(payload.size());
        if (len > max_inline_payload_for_channel(options.channel)) {
            return send_fragmented(options, type, payload);
        }

        if (options.channel == Channel::Reliable) {
            return send_reliable_message(Channel::Reliable, type, payload.data(), len,
                                         options.priority, options.lifetime_ms);
        }
        if (options.channel == Channel::ReliableOrdered) {
            std::array<U8, NetConfig::MaxReliableMessageBytes> ordered_payload{};
            ByteWriter writer{ ordered_payload.data(), ordered_payload.size() };
            auto rc = write_ordered_payload(writer, _next_ordered_sequence++, payload.data(), len);
            if (!rc.ok()) {
                return rc;
            }
            return send_reliable_message(Channel::ReliableOrdered, type,
                                         ordered_payload.data(), static_cast<U16>(writer.off),
                                         options.priority, options.lifetime_ms);
        }
        if (options.channel == Channel::SequencedUnreliable) {
            std::array<U8, NetConfig::MaxMessageBytes> sequenced_payload{};
            ByteWriter writer{ sequenced_payload.data(), sequenced_payload.size() };
            auto rc = write_sequenced_payload(writer, _next_sequenced_sequence++, payload.data(), len);
            if (!rc.ok()) {
                return rc;
            }
            return queue_message_packet(Channel::SequencedUnreliable, type,
                                        sequenced_payload.data(), static_cast<U16>(writer.off),
                                        options.priority);
        }
        return queue_message_packet(Channel::Unreliable, type, payload.data(), len, options.priority);
    }

    Result Client::send(Channel channel, U8 type, std::span<const U8> payload) {
        return send(SendOptions{ channel, SendPriority::Normal, 0 }, type, payload);
    }

    Result Client::send_text(U8 type, std::string_view text) {
        return send(SendOptions{ Channel::Unreliable, SendPriority::Normal, 0 }, type,
                    std::span<const U8>(reinterpret_cast<const U8*>(text.data()), text.size()));
    }

    Result Client::send_client_hello() {
        ClientHello hello{};
        hello.client_public_key = _ephemeral.public_key;
        hello.client_nonce = _client_nonce;
        hello.has_retry_token = _have_retry_token;
        if (hello.has_retry_token) {
            hello.retry_token = _retry_token;
        }
        hello.has_resumption_token = _config.enable_session_resumption && _have_resumption_token && !_have_retry_token && _attempted_resumption_this_connect;
        if (hello.has_resumption_token) {
            hello.resumption_token = _resumption_token;
        }

        std::array<U8, 128> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_client_hello(writer, hello);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_packet(PacketKind::Handshake, false, payload.data(), writer.off, SendPriority::High, 0);
        if (!rc.ok()) {
            return rc;
        }
        return flush_pending();
    }

    Result Client::flush_pending() {
        while (!_pending.empty()) {
            const U64 now = now_ms();
            refill_send_budget(now);

            const PendingPacket& pending = _pending.front();
            if (_send_budget_bytes < static_cast<U64>(pending.len)) {
                ++_stats.send_budget_throttles;
                ++_stats.backpressure_events;
                refresh_runtime_stats();
                return Result::success();
            }

            PacketView packet{};
            if (_config.enable_packet_debug_dumps && parse_packet(pending.bytes.data(), pending.len, packet).ok()) {
                emit_packet_debug("send", packet);
            }

            auto rc = _sock.send(pending.bytes.data(), pending.len);
            if (!rc.ok()) {
                if (rc.code == Errc::WouldBlock) {
                    ++_stats.would_block_events;
                    ++_stats.backpressure_events;
                    return Result::success();
                }
                ++_stats.socket_errors;
                return rc;
            }

            _send_budget_bytes -= static_cast<U64>(pending.len);
            ++_stats.packets_sent;
            _stats.bytes_sent += static_cast<U64>(pending.len);
            _last_send_ms = now;
            _pending_bytes -= pending.len;
            _pending.pop_front();
            refresh_runtime_stats();
        }
        return Result::success();
    }

    Result Client::pump_reliable() {
        if (_state != ConnectionState::Established) {
            return Result::success();
        }

        const U64 now = now_ms();
        const U64 before_retransmits = _reliable.retransmit_events() + _ordered_reliable.retransmit_events();
        const U64 before_losses = _reliable.loss_events() + _ordered_reliable.loss_events();

        const U32 expired_unordered = _reliable.expire_old(now);
        const U32 expired_ordered = _ordered_reliable.expire_old(now);
        if (expired_unordered > 0 || expired_ordered > 0) {
            _stats.reliable_expired += expired_unordered + expired_ordered;
            _stats.reliable_messages_dropped += expired_unordered + expired_ordered;
            _stats.ordered_messages_dropped += expired_ordered;
        }

        auto send_pending = [&](ReliableSession& session, Channel channel) -> Result {
            return session.resend_due(now, [&](PendingReliableMessage& pending) {
                auto rc = queue_message_packet(channel,
                                               pending.user_type,
                                               pending.encoded_payload.data(),
                                               static_cast<U16>(pending.encoded_payload.size()),
                                               pending.priority);
                if (!rc.ok() && rc.code == Errc::QueueFull) {
                    return Result::fail(Errc::Backpressure, "reliable send backpressure");
                }
                return rc;
            });
        };

        auto rc = send_pending(_reliable, Channel::Reliable);
        if (!rc.ok() && rc.code != Errc::Backpressure) {
            return rc;
        }
        if (!rc.ok()) {
            ++_stats.backpressure_events;
        }

        rc = send_pending(_ordered_reliable, Channel::ReliableOrdered);
        if (!rc.ok() && rc.code != Errc::Backpressure) {
            return rc;
        }
        if (!rc.ok()) {
            ++_stats.backpressure_events;
        }

        const U64 after_retransmits = _reliable.retransmit_events() + _ordered_reliable.retransmit_events();
        const U64 after_losses = _reliable.loss_events() + _ordered_reliable.loss_events();
        if (after_retransmits > before_retransmits) {
            _stats.reliable_retransmits += after_retransmits - before_retransmits;
        }
        if (after_losses > before_losses) {
            _stats.reliable_loss_events += after_losses - before_losses;
        }
        refresh_runtime_stats();
        return Result::success();
    }

    Result Client::deliver_application_message(Channel channel, U8 type, const U8* data, U16 len, U64 delivery_sequence) {
        if (channel == Channel::ReliableOrdered) {
            ++_stats.ordered_messages_received;
            U64 delivered_count = 0;
            bool buffered = false;
            bool stale = false;
            auto rc = _ordered.accept(delivery_sequence, type, data, len,
                                      [&](U8 delivered_type, const U8* delivered_data, U16 delivered_len) {
                                          ++delivered_count;
                                          if (_on_message) {
                                              MsgView msg{};
                                              msg.channel = Channel::ReliableOrdered;
                                              msg.type = delivered_type;
                                              msg.data = delivered_data;
                                              msg.len = delivered_len;
                                              _on_message(msg);
                                          }
                                          return Result::success();
                                      },
                                      buffered, stale);
            if (!rc.ok()) {
                ++_stats.ordered_messages_dropped;
                if (rc.code == Errc::QueueFull) {
                    ++_stats.backpressure_events;
                    return Result::success();
                }
                return rc;
            }
            if (buffered) {
                ++_stats.ordered_messages_buffered;
            }
            if (stale) {
                ++_stats.ordered_messages_dropped;
            }
            _stats.ordered_messages_released += delivered_count;
            return Result::success();
        }

        if (channel == Channel::SequencedUnreliable) {
            ++_stats.sequenced_messages_received;
            if (!_sequenced.accept(delivery_sequence)) {
                ++_stats.sequenced_messages_dropped;
                return Result::success();
            }
            if (_on_message) {
                MsgView msg{};
                msg.channel = Channel::SequencedUnreliable;
                msg.type = type;
                msg.data = data;
                msg.len = len;
                _on_message(msg);
            }
            return Result::success();
        }

        if (_on_message) {
            MsgView msg{};
            msg.channel = channel;
            msg.type = type;
            msg.data = data;
            msg.len = len;
            _on_message(msg);
        }
        return Result::success();
    }

    Result Client::deliver_reassembled_message(const FragmentedMessage& message) {
        ++_stats.fragmented_messages_received;
        return deliver_application_message(message.channel,
                                           message.type,
                                           message.payload.empty() ? nullptr : message.payload.data(),
                                           static_cast<U16>(message.payload.size()),
                                           message.delivery_sequence);
    }

    Result Client::handle_fragment_payload(const FragmentView& fragment) {
        bool duplicate = false;
        bool completed = false;
        auto rc = _reassembler.accept(now_ms(), fragment,
                                      [&](const FragmentedMessage& message) {
                                          return deliver_reassembled_message(message);
                                      },
                                      duplicate, completed);
        if (!rc.ok()) {
            if (rc.code == Errc::QueueFull) {
                ++_stats.reassembly_memory_rejections;
                ++_stats.reassembly_drops;
                return Result::success();
            }
            if (rc.code == Errc::TooLarge) {
                ++_stats.fragment_invalid_sets;
                ++_stats.reassembly_drops;
                return Result::success();
            }
            ++_stats.fragment_invalid_sets;
            return rc;
        }
        if (duplicate) {
            ++_stats.fragment_duplicates;
        }
        if (completed) {
            ++_stats.reassemblies_completed;
        }
        return Result::success();
    }

    void Client::dispatch_message_frame(const MsgView& msg) {
        if (msg.channel == Channel::Control) {
            if (msg.type == static_cast<U8>(ControlType::ReliableAck)) {
                ByteReader ack_reader{ msg.data, static_cast<ST>(msg.len) };
                Channel ack_channel = Channel::Reliable;
                U64 acked_message_id = 0;
                auto rc = read_reliable_ack(ack_reader, ack_channel, acked_message_id);
                if (!rc.ok()) {
                    ++_stats.bad_packets;
                    fail_connection(CloseReason::InvalidPacket, Errc::BadPacket, "malformed reliable ack");
                    return;
                }
                ReliableSession& session = (ack_channel == Channel::ReliableOrdered) ? _ordered_reliable : _reliable;
                const ReliableAckEvent ack = session.acknowledge(acked_message_id, now_ms());
                if (ack.removed) {
                    ++_stats.reliable_acks_received;
                }
                refresh_runtime_stats();
                return;
            }

            if (msg.type == static_cast<U8>(ControlType::Fragment)) {
                ByteReader reader{ msg.data, static_cast<ST>(msg.len) };
                FragmentView fragment{};
                auto rc = read_fragment_payload(reader, fragment);
                if (!rc.ok()) {
                    ++_stats.bad_packets;
                    fail_connection(CloseReason::InvalidPacket, Errc::BadPacket, "malformed fragment payload");
                    return;
                }
                ++_stats.fragments_received;
                rc = handle_fragment_payload(fragment);
                if (!rc.ok()) {
                    ++_stats.bad_packets;
                    fail_connection(CloseReason::InvalidPacket, rc.code, "fragment handling failed");
                }
                return;
            }

            ++_stats.protocol_errors;
            fail_connection(CloseReason::ProtocolError, Errc::ProtocolError, "unknown control message");
            return;
        }

        if (msg.channel == Channel::Reliable || msg.channel == Channel::ReliableOrdered) {
            ByteReader reliable_reader{ msg.data, static_cast<ST>(msg.len) };
            ReliablePayloadView reliable{};
            auto rc = read_reliable_payload(reliable_reader, reliable);
            if (!rc.ok()) {
                ++_stats.bad_packets;
                fail_connection(CloseReason::InvalidPacket, Errc::BadPacket, "malformed reliable payload");
                return;
            }

            (void)queue_control_ack(msg.channel, reliable.message_id);
            ReliableSession& session = (msg.channel == Channel::ReliableOrdered) ? _ordered_reliable : _reliable;
            if (!session.accept_incoming(reliable.message_id)) {
                return;
            }

            ++_stats.reliable_messages_delivered;
            if (msg.type == static_cast<U8>(ControlType::Fragment)) {
                ByteReader fragment_reader{ reliable.data, static_cast<ST>(reliable.len) };
                FragmentView fragment{};
                auto fragment_rc = read_fragment_payload(fragment_reader, fragment);
                if (fragment_rc.ok()) {
                    ++_stats.fragments_received;
                    rc = handle_fragment_payload(fragment);
                    if (!rc.ok()) {
                        ++_stats.bad_packets;
                        fail_connection(CloseReason::InvalidPacket, rc.code, "fragment handling failed");
                    }
                    return;
                }
            }

            if (msg.channel == Channel::ReliableOrdered) {
                ByteReader ordered_reader{ reliable.data, static_cast<ST>(reliable.len) };
                OrderedPayloadView ordered{};
                rc = read_ordered_payload(ordered_reader, ordered);
                if (!rc.ok()) {
                    ++_stats.bad_packets;
                    fail_connection(CloseReason::InvalidPacket, Errc::BadPacket, "malformed ordered payload");
                    return;
                }
                rc = deliver_application_message(Channel::ReliableOrdered, msg.type,
                                                 ordered.data, ordered.len, ordered.delivery_sequence);
                if (!rc.ok()) {
                    ++_stats.protocol_errors;
                    fail_connection(CloseReason::ProtocolError, rc.code, "ordered delivery failed");
                }
                return;
            }

            auto deliver_rc = deliver_application_message(Channel::Reliable, msg.type,
                                                          reliable.data, reliable.len, 0);
            if (!deliver_rc.ok()) {
                ++_stats.protocol_errors;
                fail_connection(CloseReason::ProtocolError, deliver_rc.code, "reliable delivery failed");
            }
            return;
        }

        if (msg.channel == Channel::SequencedUnreliable) {
            ByteReader sequenced_reader{ msg.data, static_cast<ST>(msg.len) };
            SequencedPayloadView sequenced{};
            auto rc = read_sequenced_payload(sequenced_reader, sequenced);
            if (!rc.ok()) {
                ++_stats.bad_packets;
                fail_connection(CloseReason::InvalidPacket, Errc::BadPacket, "malformed sequenced payload");
                return;
            }
            rc = deliver_application_message(Channel::SequencedUnreliable, msg.type,
                                             sequenced.data, sequenced.len, sequenced.delivery_sequence);
            if (!rc.ok()) {
                ++_stats.protocol_errors;
                fail_connection(CloseReason::ProtocolError, rc.code, "sequenced delivery failed");
            }
            return;
        }

        auto rc = deliver_application_message(msg.channel, msg.type, msg.data, msg.len, 0);
        if (!rc.ok()) {
            ++_stats.protocol_errors;
            fail_connection(CloseReason::ProtocolError, rc.code, "application delivery failed");
        }
    }

    void Client::dispatch_message_payload(const U8* payload, ST payload_len) {
        ByteReader reader{ payload, payload_len };
        for (;;) {
            MsgView msg{};
            auto rc = read_message(reader, msg);
            if (rc.code == Errc::EndOfStream) {
                break;
            }
            if (!rc.ok()) {
                ++_stats.bad_packets;
                fail_connection(CloseReason::InvalidPacket, rc.code, "malformed message frame");
                return;
            }
            ++_stats.message_frames_received;
            dispatch_message_frame(msg);
            if (_state == ConnectionState::Closed) {
                return;
            }
        }
    }

    Result Client::handle_retry_packet(const PacketView& packet) {
        ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
        RetryToken token{};
        auto rc = read_retry(reader, token);
        if (!rc.ok()) {
            return rc;
        }

        if (_attempted_resumption_this_connect && !_have_retry_token) {
            ++_stats.session_resumptions_rejected;
        }
        _retry_token = token;
        _have_retry_token = true;
        ++_stats.handshake_retries_received;
        emit_log(LogLevel::Trace, "client received retry token");
        return send_client_hello();
    }

    Result Client::handle_server_hello_packet(const PacketView& packet) {
        ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
        ServerHello hello{};
        auto rc = read_server_hello(reader, hello);
        if (!rc.ok()) {
            return rc;
        }

        ClientHello client_hello{};
        client_hello.client_public_key = _ephemeral.public_key;
        client_hello.client_nonce = _client_nonce;
        client_hello.has_retry_token = _have_retry_token;
        if (_have_retry_token) {
            client_hello.retry_token = _retry_token;
        }
        client_hello.has_resumption_token = _config.enable_session_resumption && _have_resumption_token && !_have_retry_token && _attempted_resumption_this_connect;
        if (client_hello.has_resumption_token) {
            client_hello.resumption_token = _resumption_token;
        }

        SessionKeys candidate_keys{};
        rc = crypto_derive_client_session_keys(_ephemeral,
                                               hello.server_public_key.data(), hello.server_public_key.size(),
                                               candidate_keys);
        if (!rc.ok()) {
            return rc;
        }

        std::array<U8, 320> transcript{};
        ST transcript_len = 0;
        rc = build_transcript_mac_input(client_hello, hello, transcript.data(), transcript.size(), transcript_len);
        if (!rc.ok()) {
            candidate_keys.clear();
            return rc;
        }

        std::array<U8, NetConfig::TranscriptMacBytes> expected_mac{};
        rc = crypto_keyed_hash(candidate_keys.rx.data(), candidate_keys.rx.size(),
                               transcript.data(), transcript_len,
                               expected_mac.data(), expected_mac.size());
        if (!rc.ok()) {
            candidate_keys.clear();
            return rc;
        }

        if (!crypto_constant_time_equal(expected_mac.data(), hello.transcript_mac.data(), expected_mac.size())) {
            candidate_keys.clear();
            return Result::fail(Errc::AuthFailed, "server hello MAC mismatch");
        }

        _session_keys.clear();
        _session_keys = candidate_keys;
        crypto_secure_zero(_ephemeral.secret_key.data(), _ephemeral.secret_key.size());
        _conn_id = hello.server_conn_id;
        _server_nonce = hello.server_nonce;
        _packet_window.reset();
        _last_recv_ms = now_ms();

        if (hello.has_resumption_token) {
            _resumption_token = hello.resumption_token;
            _have_resumption_token = true;
        } else {
            _have_resumption_token = false;
            _resumption_token = {};
        }
        if (_attempted_resumption_this_connect && !_have_retry_token) {
            ++_stats.session_resumptions_accepted;
        }

        rc = queue_keepalive();
        if (!rc.ok()) {
            fail_connection(CloseReason::InternalError, rc.code, "failed to send client finish");
            return rc;
        }

        transition_state(ConnectionState::Established);
        ++_stats.sessions_established;
        ++_stats.handshake_successes;
        refresh_runtime_stats();
        emit_log(LogLevel::Info, "client handshake established");
        return Result::success();
    }

    Result Client::handle_handshake_packet(const PacketView& packet) {
        if (packet_header_encrypted(packet.h)) {
            return Result::fail(Errc::ProtocolError, "encrypted handshake packet is illegal");
        }
        if (_state != ConnectionState::Handshaking) {
            return Result::fail(Errc::StateError, "handshake packet received in wrong state");
        }
        if (!packet.payload || packet.h.payload_len == 0) {
            return Result::fail(Errc::BadPacket, "empty handshake packet");
        }

        const U8 type = packet.payload[0];
        if (type == static_cast<U8>(HandshakeType::Retry)) {
            return handle_retry_packet(packet);
        }
        if (type == static_cast<U8>(HandshakeType::ServerHello)) {
            return handle_server_hello_packet(packet);
        }
        return Result::fail(Errc::ProtocolError, "unexpected handshake packet type");
    }

    Result Client::handle_established_packet(const PacketView& packet) {
        if (!packet_header_encrypted(packet.h)) {
            return Result::fail(Errc::ProtocolError, "unencrypted secure packet");
        }
        if (_session_keys.empty()) {
            return Result::fail(Errc::StateError, "session keys missing");
        }
        if (packet.h.conn_id != _conn_id) {
            return Result::fail(Errc::ProtocolError, "unexpected connection id");
        }

        std::array<U8, NetConfig::PacketHeaderBytes> aad{};
        ByteWriter aad_writer{ aad.data(), aad.size() };
        auto rc = write_packet_header(aad_writer, packet.h);
        if (!rc.ok()) {
            return rc;
        }

        std::array<U8, NetConfig::AeadNonceBytes> nonce{};
        crypto_make_packet_nonce(packet.h.conn_id, packet.h.seq, nonce);

        std::array<U8, NetConfig::MaxEncryptedPlaintextBytes> plaintext{};
        ST plaintext_len = 0;
        rc = crypto_aead_decrypt(_session_keys.rx.data(), _session_keys.rx.size(),
                                 nonce.data(), nonce.size(),
                                 aad.data(), aad_writer.off,
                                 packet.payload, packet.h.payload_len,
                                 plaintext.data(), plaintext.size(), plaintext_len);
        if (!rc.ok()) {
            ++_stats.auth_failures;
            ++_stats.decrypt_failures;
            return rc;
        }

        if (packet.h.seq == 0) {
            return Result::fail(Errc::ProtocolError, "encrypted packet sequence is invalid");
        }

        if (!_packet_window.accept(packet.h.seq)) {
            ++_stats.replays_dropped;
            return Result::fail(Errc::Replay, "replayed packet");
        }

        _last_recv_ms = now_ms();
        PacketView logical{};
        logical.h = packet.h;
        logical.h.payload_len = static_cast<U32>(plaintext_len);
        logical.payload = (plaintext_len == 0) ? nullptr : plaintext.data();

        if (_on_packet) {
            _on_packet(logical);
        }
        emit_packet_debug("recv", logical);

        switch (static_cast<PacketKind>(packet.h.kind)) {
        case PacketKind::Raw:
            return Result::success();
        case PacketKind::Message:
            dispatch_message_payload(logical.payload, logical.h.payload_len);
            return (_state == ConnectionState::Closed) ? Result::fail(Errc::Closed, "connection closed") : Result::success();
        case PacketKind::Keepalive:
            ++_stats.keepalives_received;
            return Result::success();
        case PacketKind::Close: {
            ByteReader reader{ logical.payload, logical.h.payload_len };
            CloseFrame close_frame{};
            rc = read_close_frame(reader, close_frame);
            if (!rc.ok()) {
                ++_stats.bad_packets;
                return rc;
            }
            ++_stats.closes_received;
            _close_reason = close_frame.reason;
            _sock.close();
            _session_keys.clear();
            _reliable.clear();
            _ordered_reliable.clear();
            _pending.clear();
            _pending_bytes = 0;
            transition_state(ConnectionState::Closed);
            return Result::fail(Errc::Closed, "remote closed connection");
        }
        case PacketKind::Handshake:
            return Result::fail(Errc::ProtocolError, "handshake packet in secure path");
        }

        return Result::fail(Errc::ProtocolError, "unknown packet kind");
    }

    void Client::handle_packet(const PacketView& packet) {
        Result rc;
        if (static_cast<PacketKind>(packet.h.kind) == PacketKind::Handshake) {
            if (_on_packet) {
                _on_packet(packet);
            }
            emit_packet_debug("recv", packet);
            rc = handle_handshake_packet(packet);
        } else if (static_cast<PacketKind>(packet.h.kind) == PacketKind::Close &&
                   _state == ConnectionState::Handshaking && !packet_header_encrypted(packet.h)) {
            if (_on_packet) {
                _on_packet(packet);
            }
            emit_packet_debug("recv", packet);
            ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
            CloseFrame close_frame{};
            rc = read_close_frame(reader, close_frame);
            if (rc.ok()) {
                ++_stats.closes_received;
                _close_reason = close_frame.reason;
                _sock.close();
                _session_keys.clear();
                _reliable.clear();
                _ordered_reliable.clear();
                _pending.clear();
                _pending_bytes = 0;
                transition_state(ConnectionState::Closed);
                return;
            }
        } else {
            rc = handle_established_packet(packet);
            if (rc.code == Errc::Replay) {
                return;
            }
        }

        if (!rc.ok()) {
            if (rc.code == Errc::UnsupportedVersion) {
                ++_stats.unsupported_version_packets;
                fail_connection(CloseReason::UnsupportedVersion, rc.code, "unsupported version");
            } else if (rc.code == Errc::AuthFailed) {
                fail_connection(CloseReason::AuthenticationFailed, rc.code, "authentication failed");
            } else if (rc.code == Errc::ProtocolError || rc.code == Errc::StateError) {
                ++_stats.protocol_errors;
                fail_connection(CloseReason::ProtocolError, rc.code, "protocol error");
            } else if (rc.code == Errc::BadPacket || rc.code == Errc::Truncated) {
                ++_stats.bad_packets;
                fail_connection(CloseReason::InvalidPacket, rc.code, "invalid packet");
            }
        }
    }

    Result Client::pump_receive() {
        for (;;) {
            ST n = 0;
            auto rc = _sock.recv(_rxbuf.data(), _rxbuf.size(), n);
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

            PacketView packet{};
            rc = parse_packet(_rxbuf.data(), n, packet);
            if (!rc.ok()) {
                if (rc.code == Errc::UnsupportedVersion) {
                    ++_stats.unsupported_version_packets;
                    fail_connection(CloseReason::UnsupportedVersion, rc.code, "unsupported version");
                } else {
                    ++_stats.bad_packets;
                    fail_connection(CloseReason::InvalidPacket, rc.code, "parse failed");
                }
                return Result::success();
            }

            handle_packet(packet);
            if (_state == ConnectionState::Closed) {
                return Result::success();
            }
        }

        return Result::success();
    }

    Result Client::run_housekeeping() {
        const U64 now = now_ms();
        _reassembler.expire_old(now, [&](U64) {
            ++_stats.reassemblies_expired;
            ++_stats.reassembly_drops;
        });

        if (_state == ConnectionState::Handshaking) {
            if (_handshake_started_ms != 0 && (now - _handshake_started_ms) > _config.handshake_timeout_ms) {
                ++_stats.establish_timeouts;
                fail_connection(CloseReason::EstablishTimeout, Errc::Timeout, "handshake timeout");
            }
            refresh_runtime_stats();
            return Result::success();
        }

        if (_state == ConnectionState::Established) {
            if (_last_recv_ms != 0 && (now - _last_recv_ms) > _config.idle_timeout_ms) {
                ++_stats.idle_timeouts;
                auto rc = queue_close_packet(CloseReason::IdleTimeout, true);
                (void)rc;
                _close_reason = CloseReason::IdleTimeout;
                transition_state(ConnectionState::Closing);
                refresh_runtime_stats();
                return Result::success();
            }
            if (_last_send_ms == 0 || (now - _last_send_ms) >= _config.keepalive_interval_ms) {
                auto rc = queue_keepalive();
                refresh_runtime_stats();
                return rc;
            }
        }

        if (_state == ConnectionState::Closing && _last_send_ms != 0 && (now - _last_send_ms) >= _config.close_drain_ms) {
            _sock.close();
            _session_keys.clear();
            _reliable.clear();
            _ordered_reliable.clear();
            _pending.clear();
            _pending_bytes = 0;
            transition_state(ConnectionState::Closed);
        }

        refresh_runtime_stats();
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
        rc = pump_receive();
        if (!rc.ok()) {
            return rc;
        }
        return run_housekeeping();
    }

    Result Client::context_poll() {
        return tick();
    }

    Result Client::close(CloseReason reason) {
        if (_state == ConnectionState::Closed || _state == ConnectionState::Idle) {
            return Result::success();
        }

        const bool encrypted = (_state == ConnectionState::Established || _state == ConnectionState::Closing);
        auto rc = queue_close_packet(reason, encrypted);
        if (!rc.ok()) {
            fail_connection(reason, rc.code, "failed to queue close packet");
            return rc;
        }

        _close_reason = reason;
        transition_state(ConnectionState::Closing);
        refresh_runtime_stats();
        return Result::success();
    }

    Result Client::local_endpoint(Endpoint& out) const {
        return _sock.local_endpoint(out);
    }

} // namespace scn
