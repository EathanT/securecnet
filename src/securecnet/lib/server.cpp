#include "securecnet/server.hpp"

#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"
#include "securecnet/platform.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

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

    Result Server::Peer::send(const SendOptions& options, U8 type, std::span<const U8> payload) const {
        if (!_owner) {
            return Result::fail(Errc::InvalidArg, "peer is not bound to a server");
        }
        return _owner->send(*this, options, type, payload);
    }

    Result Server::Peer::send(Channel channel, U8 type, std::span<const U8> payload) const {
        return send(SendOptions{ channel, SendPriority::Normal, 0 }, type, payload);
    }

    Result Server::Peer::send_text(U8 type, std::string_view text) const {
        return send_text(type, text, SendOptions{ Channel::Unreliable, SendPriority::Normal, 0 });
    }

    Result Server::Peer::send_text(U8 type, std::string_view text, const SendOptions& options) const {
        if (text.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::TooLarge, "text payload too large");
        }
        return send(options, type,
                    std::span<const U8>(reinterpret_cast<const U8*>(text.data()), text.size()));
    }

    Result Server::Peer::send_unreliable(U8 type, std::span<const U8> payload, SendPriority priority) const {
        return send(SendOptions{ Channel::Unreliable, priority, 0 }, type, payload);
    }

    Result Server::Peer::send_reliable(U8 type, std::span<const U8> payload, SendPriority priority, U64 lifetime_ms) const {
        return send(SendOptions{ Channel::Reliable, priority, lifetime_ms }, type, payload);
    }

    Result Server::Peer::send_ordered(U8 type, std::span<const U8> payload, SendPriority priority, U64 lifetime_ms) const {
        return send(SendOptions{ Channel::ReliableOrdered, priority, lifetime_ms }, type, payload);
    }

    Result Server::Peer::send_latest(U8 type, std::span<const U8> payload, SendPriority priority) const {
        return send(SendOptions{ Channel::SequencedUnreliable, priority, 0 }, type, payload);
    }

    Result Server::Peer::send_unreliable_text(U8 type, std::string_view text, SendPriority priority) const {
        return send_text(type, text, SendOptions{ Channel::Unreliable, priority, 0 });
    }

    Result Server::Peer::send_reliable_text(U8 type, std::string_view text, SendPriority priority, U64 lifetime_ms) const {
        return send_text(type, text, SendOptions{ Channel::Reliable, priority, lifetime_ms });
    }

    Result Server::Peer::send_ordered_text(U8 type, std::string_view text, SendPriority priority, U64 lifetime_ms) const {
        return send_text(type, text, SendOptions{ Channel::ReliableOrdered, priority, lifetime_ms });
    }

    Result Server::Peer::send_latest_text(U8 type, std::string_view text, SendPriority priority) const {
        return send_text(type, text, SendOptions{ Channel::SequencedUnreliable, priority, 0 });
    }

    Result Server::Peer::close(CloseReason reason) const {
        if (!_owner) {
            return Result::fail(Errc::InvalidArg, "peer is not bound to a server");
        }
        return _owner->close_peer(*this, reason);
    }

    Result Server::Peer::set_user_data(void* data) const {
        if (!_owner) {
            return Result::fail(Errc::InvalidArg, "peer is not bound to a server");
        }
        return _owner->set_peer_user_data(*this, data);
    }

    void* Server::Peer::user_data() const {
        return _owner ? _owner->peer_user_data(*this) : nullptr;
    }

    Server::Server() {
        refresh_runtime_stats();
    }

    Server::Server(const ServerConfig& config) : _config(config) {
        refresh_runtime_stats();
    }

    Server::Server(IoContext& ctx) : Server() {
        _ctx = &ctx;
        _ctx->register_service(this);
    }

    Server::Server(const ServerConfig& config, IoContext& ctx) : Server(config) {
        _ctx = &ctx;
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

    void Server::emit_log(LogLevel level, std::string_view msg) const {
        if (_logger) {
            _logger(level, msg);
        }
    }

    void Server::emit_packet_debug(std::string_view direction, const Endpoint& endpoint, const PacketView& packet) const {
        if (_config.enable_packet_debug_dumps && _packet_debug) {
            _packet_debug(direction, endpoint, packet);
        }
    }

    void Server::emit_backpressure(const Peer& peer, Channel channel, U8 type, Result rc) {
        if (!_on_backpressure) {
            return;
        }
        BackpressureInfo info{};
        info.code = rc.code;
        info.channel = channel;
        info.type = type;
        info.queued_packets = _pending.size();
        info.queued_bytes = _pending_bytes;
        if (auto* session = find_session(peer.conn_id())) {
            info.send_budget_bytes = session->send_budget_bytes;
        }
        _on_backpressure(peer, info);
    }

    Result Server::runtime_status() const {
        auto rc = _ctx ? _ctx->runtime_status() : _runtime.status();
        if (!rc.ok()) {
            return rc;
        }
        return crypto_runtime_status();
    }

    Server::Peer Server::make_peer(PeerSession& session) {
        return Peer{ this, session.endpoint, session.conn_id, session.peer_id };
    }

    Server::Peer Server::make_peer(const PeerSession& session) const {
        return Peer{ const_cast<Server*>(this), session.endpoint, session.conn_id, session.peer_id };
    }

    void Server::transition_state(PeerSession& session, ConnectionState next) {
        if (session.state == next) {
            return;
        }
        const ConnectionState previous = session.state;
        session.state = next;
        ++_stats.state_transitions;
        refresh_runtime_stats();
        emit_log(LogLevel::Trace, "server session state transition");
        Peer peer = make_peer(session);
        if (_on_peer_state_change) {
            _on_peer_state_change(peer, previous, next);
        }
        if (previous != ConnectionState::Established && next == ConnectionState::Established) {
            if (_on_peer_connected) {
                _on_peer_connected(peer);
            }
            if (_on_peer_ready) {
                _on_peer_ready(peer);
            }
        }
        if (previous != ConnectionState::Closed && next == ConnectionState::Closed && _on_peer_disconnected) {
            _on_peer_disconnected(peer, session.close_reason);
        }
    }

    void Server::refresh_runtime_stats() {
        _stats.current_peer_count = _sessions.size();
        _stats.current_pending_packets = _pending.size();
        _stats.current_reliable_pending = 0;
        _stats.current_reliable_inflight = 0;
        _stats.current_reassembly_count = 0;
        _stats.current_reassembly_memory_bytes = 0;
        _stats.current_send_budget_bytes = 0;
        _stats.rtt_latest_ms = 0;
        _stats.rtt_smoothed_ms = 0;
        _stats.rtt_variance_ms = 0;
        _stats.current_retransmit_timeout_ms = 0;
        _stats.estimated_loss_per_mille = 0;
        _stats.congestion_current_rate_bytes_per_second = 0;
        _stats.congestion_current_window_bytes = 0;
        _stats.congestion_ack_events = 0;
        _stats.congestion_loss_events = 0;
        _stats.congestion_backpressure_events = 0;

        for (const auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            _stats.current_reliable_pending += session.reliable.pending_count() + session.ordered_reliable.pending_count();
            _stats.current_reliable_inflight += session.reliable.inflight_count() + session.ordered_reliable.inflight_count();
            _stats.current_reassembly_count += session.reassembler.active_count();
            _stats.current_reassembly_memory_bytes += session.reassembler.memory_bytes();
            _stats.current_send_budget_bytes += session.send_budget_bytes;
            _stats.rtt_latest_ms = (std::max<U64>)(_stats.rtt_latest_ms,
                                                 (std::max)(session.reliable.latest_rtt_ms(),
                                                          session.ordered_reliable.latest_rtt_ms()));
            _stats.rtt_smoothed_ms = (std::max<U64>)(_stats.rtt_smoothed_ms,
                                                   (std::max)(session.reliable.smoothed_rtt_ms(),
                                                            session.ordered_reliable.smoothed_rtt_ms()));
            _stats.rtt_variance_ms = (std::max<U64>)(_stats.rtt_variance_ms,
                                                   (std::max)(session.reliable.rtt_variance_ms(),
                                                            session.ordered_reliable.rtt_variance_ms()));
            _stats.current_retransmit_timeout_ms = (std::max<U64>)(_stats.current_retransmit_timeout_ms,
                                                                 (std::max)(session.reliable.rto_ms(),
                                                                          session.ordered_reliable.rto_ms()));
            _stats.estimated_loss_per_mille = (std::max<U64>)(_stats.estimated_loss_per_mille,
                                                            (std::max)(session.reliable.loss_per_mille(),
                                                                     session.ordered_reliable.loss_per_mille()));
            const auto congestion = session.congestion.snapshot();
            _stats.congestion_current_rate_bytes_per_second += congestion.current_rate_bytes_per_second;
            _stats.congestion_current_window_bytes += congestion.current_window_bytes;
            _stats.congestion_ack_events += congestion.ack_events;
            _stats.congestion_loss_events += congestion.loss_events;
            _stats.congestion_backpressure_events += congestion.backpressure_events;
        }
    }

    Result Server::listen(const Endpoint& bind_ep) {
        auto rc = runtime_status();
        if (!rc.ok()) {
            return rc;
        }
        rc = validate_server_config(_config);
        if (!rc.ok()) {
            return rc;
        }

        stop();
        const int family = reinterpret_cast<const sockaddr*>(&bind_ep.addr)->sa_family;
        rc = _sock.open(family);
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

        _stateless_seq = 1;
        _pending.clear();
        _pending_bytes = 0;
        _sessions.clear();
        _endpoint_to_conn.clear();
        _ip_abuse.clear();
        _preauth.clear();
        crypto_random_bytes(_cookie_secret.data(), _cookie_secret.size());
        _stats.reset();
        refresh_runtime_stats();
        emit_log(LogLevel::Info, "server listening");
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
        for (auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            session.keys.clear();
            session.ephemeral.clear();
            session.reliable.clear();
            session.ordered_reliable.clear();
            session.ordered.clear();
            session.sequenced.clear();
            session.reassembler.clear();
        }
        _pending.clear();
        _pending_bytes = 0;
        _sessions.clear();
        _endpoint_to_conn.clear();
        _ip_abuse.clear();
        _preauth.clear();
        _sock.close();
        _stateless_seq = 1;
        refresh_runtime_stats();
    }

    std::string Server::endpoint_host_key(const Endpoint& endpoint) {
        const sockaddr* sa = reinterpret_cast<const sockaddr*>(&endpoint.addr);
        char host[INET6_ADDRSTRLEN]{};
        if (endpoint.len == 0) {
            return "<uninitialized>";
        }
        if (sa->sa_family == AF_INET) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
            if (inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host))) {
                return host;
            }
        } else if (sa->sa_family == AF_INET6) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
            if (inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host))) {
                return host;
            }
        }
        return endpoint.to_string();
    }

    Server::IpAbuseState& Server::abuse_state_for(const Endpoint& endpoint) {
        return _ip_abuse[endpoint_host_key(endpoint)];
    }

    Server::PreauthBudgetState& Server::preauth_state_for(const Endpoint& endpoint) {
        return _preauth[endpoint_host_key(endpoint)];
    }

    bool Server::endpoint_rate_limited(const Endpoint& endpoint, U64 now) {
        IpAbuseState& state = abuse_state_for(endpoint);
        if (state.window_started_ms == 0 || now < state.window_started_ms || (now - state.window_started_ms) >= 1000) {
            state.window_started_ms = now;
            state.handshakes_in_window = 0;
        }
        if (state.handshakes_in_window >= _config.abuse.per_ip_handshake_rate_limit_per_second) {
            ++_stats.rate_limited_packets;
            ++_stats.dropped_packets;
            return true;
        }
        ++state.handshakes_in_window;
        return false;
    }

    bool Server::endpoint_is_banned(const Endpoint& endpoint, U64 now) {
        const IpAbuseState& state = abuse_state_for(endpoint);
        return state.banned_until_ms > now;
    }

    void Server::note_invalid_packet(const Endpoint& endpoint, U64 now) {
        IpAbuseState& state = abuse_state_for(endpoint);
        if (state.banned_until_ms > now) {
            return;
        }
        ++state.invalid_penalty_score;
        ++_stats.invalid_packet_penalties;
        if (state.invalid_penalty_score >= _config.abuse.invalid_packet_ban_threshold) {
            state.invalid_penalty_score = 0;
            state.banned_until_ms = now + _config.abuse.invalid_packet_ban_ms;
            ++_stats.rate_limited_packets;
        }
    }

    bool Server::can_amplify_to(const Endpoint& endpoint, U64 bytes_to_send, U64 now) {
        PreauthBudgetState& state = preauth_state_for(endpoint);
        state.last_seen_ms = now;
        const U64 allowance = (state.bytes_received * _config.abuse.anti_amplification_factor) +
                              _config.abuse.anti_amplification_slack_bytes;
        if ((state.bytes_sent + bytes_to_send) > allowance) {
            ++_stats.amplification_drops;
            ++_stats.dropped_packets;
            return false;
        }
        return true;
    }

    void Server::note_preauth_receive(const Endpoint& endpoint, U64 bytes_received, U64 now) {
        PreauthBudgetState& state = preauth_state_for(endpoint);
        state.bytes_received += bytes_received;
        state.last_seen_ms = now;
    }

    void Server::note_preauth_send(const Endpoint& endpoint, U64 bytes_sent, U64 now) {
        PreauthBudgetState& state = preauth_state_for(endpoint);
        state.bytes_sent += bytes_sent;
        state.last_seen_ms = now;
    }

    U64 Server::total_reassembly_memory_bytes() const {
        U64 total = 0;
        for (const auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            total += session.reassembler.memory_bytes();
        }
        return total;
    }

    RetryToken Server::make_retry_token(const Endpoint& from, const ClientHello& hello, U64 issued_at_ms) const {
        RetryToken token{};
        token.issued_at_ms = issued_at_ms;

        std::array<U8, 256> input{};
        ByteWriter writer{ input.data(), input.size() };
        const std::string endpoint_string = from.to_string();
        (void)writer.write_u64(issued_at_ms);
        (void)writer.write_u16(NetConfig::ProtocolVersion);
        (void)writer.write_u16(static_cast<U16>(endpoint_string.size()));
        (void)writer.write_bytes(endpoint_string.data(), endpoint_string.size());
        (void)writer.write_bytes(hello.client_public_key.data(), hello.client_public_key.size());
        (void)writer.write_bytes(hello.client_nonce.data(), hello.client_nonce.size());
        (void)crypto_keyed_hash(_cookie_secret.data(), _cookie_secret.size(),
                                input.data(), writer.off,
                                token.mac.data(), token.mac.size());
        return token;
    }

    Result Server::validate_retry_token(const Endpoint& from, const ClientHello& hello,
                                        const RetryToken& token, U64 now) const {
        if (token.issued_at_ms > now || (now - token.issued_at_ms) > NetConfig::RetryTokenLifetimeMs) {
            return Result::fail(Errc::Timeout, "retry token expired");
        }
        RetryToken expected = make_retry_token(from, hello, token.issued_at_ms);
        if (!crypto_constant_time_equal(expected.mac.data(), token.mac.data(), token.mac.size())) {
            return Result::fail(Errc::AuthFailed, "retry token MAC mismatch");
        }
        return Result::success();
    }

    ResumptionToken Server::make_resumption_token(const Endpoint& from, U64 issued_at_ms) const {
        ResumptionToken token{};
        token.issued_at_ms = issued_at_ms;
        token.expires_at_ms = issued_at_ms + NetConfig::ResumptionTokenLifetimeMs;
        do {
            crypto_random_bytes(&token.ticket_id, sizeof(token.ticket_id));
        } while (token.ticket_id == 0);

        std::array<U8, 256> input{};
        ByteWriter writer{ input.data(), input.size() };
        const std::string host_key = endpoint_host_key(from);
        (void)writer.write_u64(token.issued_at_ms);
        (void)writer.write_u64(token.expires_at_ms);
        (void)writer.write_u64(token.ticket_id);
        (void)writer.write_u16(NetConfig::ProtocolVersion);
        (void)writer.write_u16(static_cast<U16>(host_key.size()));
        (void)writer.write_bytes(host_key.data(), host_key.size());
        (void)crypto_keyed_hash(_cookie_secret.data(), _cookie_secret.size(),
                                input.data(), writer.off,
                                token.mac.data(), token.mac.size());
        return token;
    }

    Result Server::validate_resumption_token(const Endpoint& from, const ResumptionToken& token, U64 now) const {
        if (token.ticket_id == 0) {
            return Result::fail(Errc::BadPacket, "resumption token missing ticket id");
        }
        if (token.issued_at_ms > now || token.expires_at_ms <= token.issued_at_ms || now > token.expires_at_ms) {
            return Result::fail(Errc::Timeout, "resumption token expired");
        }

        std::array<U8, 256> input{};
        ByteWriter writer{ input.data(), input.size() };
        const std::string host_key = endpoint_host_key(from);
        Result rc = writer.write_u64(token.issued_at_ms);
        if (!rc.ok()) return rc;
        rc = writer.write_u64(token.expires_at_ms);
        if (!rc.ok()) return rc;
        rc = writer.write_u64(token.ticket_id);
        if (!rc.ok()) return rc;
        rc = writer.write_u16(NetConfig::ProtocolVersion);
        if (!rc.ok()) return rc;
        rc = writer.write_u16(static_cast<U16>(host_key.size()));
        if (!rc.ok()) return rc;
        rc = writer.write_bytes(host_key.data(), host_key.size());
        if (!rc.ok()) return rc;

        std::array<U8, NetConfig::ResumptionTokenMacBytes> expected_mac{};
        rc = crypto_keyed_hash(_cookie_secret.data(), _cookie_secret.size(),
                               input.data(), writer.off,
                               expected_mac.data(), expected_mac.size());
        if (!rc.ok()) {
            return rc;
        }
        if (!crypto_constant_time_equal(expected_mac.data(), token.mac.data(), token.mac.size())) {
            return Result::fail(Errc::AuthFailed, "resumption token MAC mismatch");
        }
        return Result::success();
    }

    Result Server::enqueue_pending_packet(PendingPacket&& pending) {
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

    Result Server::queue_packet(const Endpoint& to, PacketKind kind, bool encrypted,
                                const U8* payload, ST payload_len,
                                U64 conn_id, U64 seq,
                                const SessionKeys* keys,
                                SendPriority priority,
                                U64 owner_conn_id) {
        if (payload_len > 0 && !payload) {
            return Result::fail(Errc::InvalidArg, "payload is null");
        }
        if (encrypted && payload_len > NetConfig::MaxEncryptedPlaintextBytes) {
            return Result::fail(Errc::InvalidArg, "encrypted payload too large");
        }
        if (!encrypted && payload_len > NetConfig::MaxPayloadBytes) {
            return Result::fail(Errc::InvalidArg, "payload too large");
        }
        if (encrypted && (!keys || keys->empty())) {
            return Result::fail(Errc::StateError, "missing session keys");
        }
        if (!encrypted) {
            const U64 estimated_bytes = static_cast<U64>(packet_header_bytes() + payload_len);
            if (!can_amplify_to(to, estimated_bytes, now_ms())) {
                return Result::success();
            }
        }

        PacketHeader header{};
        header.kind = static_cast<U8>(kind);
        header.flags = encrypted ? PacketFlagEncrypted : 0;
        header.conn_id = conn_id;
        header.seq = seq;

        std::array<U8, NetConfig::MaxPayloadBytes> packet_payload{};
        ST packet_payload_len = payload_len;
        if (encrypted) {
            header.payload_len = static_cast<U32>(payload_len + NetConfig::AeadTagBytes);
            std::array<U8, NetConfig::PacketHeaderBytes> aad{};
            ByteWriter aad_writer{ aad.data(), aad.size() };
            auto rc = write_packet_header(aad_writer, header);
            if (!rc.ok()) {
                return rc;
            }

            std::array<U8, NetConfig::AeadNonceBytes> nonce{};
            crypto_make_packet_nonce(conn_id, seq, nonce);
            rc = crypto_aead_encrypt(keys->tx.data(), keys->tx.size(),
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
        pending.to = to;
        pending.owner_conn_id = owner_conn_id;
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

    Result Server::queue_plain_handshake(const Endpoint& to, const U8* payload, ST payload_len, U64 conn_id) {
        return queue_packet(to, PacketKind::Handshake, false, payload, payload_len,
                            conn_id, _stateless_seq++, nullptr, SendPriority::High, 0);
    }

    Result Server::queue_retry(const Endpoint& to, const RetryToken& token) {
        std::array<U8, 64> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_retry(writer, token);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_plain_handshake(to, payload.data(), writer.off, 0);
        if (rc.ok()) {
            ++_stats.handshake_retries_sent;
        }
        return rc;
    }

    Result Server::queue_server_hello(PeerSession& session) {
        ClientHello client_hello{};
        client_hello.client_public_key = session.client_public_key;
        client_hello.client_nonce = session.client_nonce;
        client_hello.has_retry_token = session.handshake_had_retry_token;
        if (client_hello.has_retry_token) {
            client_hello.retry_token = session.handshake_retry_token;
        }
        client_hello.has_resumption_token = session.handshake_had_resumption_token;
        if (client_hello.has_resumption_token) {
            client_hello.resumption_token = session.handshake_resumption_token;
        }

        ServerHello hello{};
        hello.server_conn_id = session.conn_id;
        hello.server_public_key = session.ephemeral.public_key;
        hello.server_nonce = session.server_nonce;
        hello.has_resumption_token = _config.enable_session_resumption;
        if (hello.has_resumption_token) {
            hello.resumption_token = make_resumption_token(session.endpoint, now_ms());
        }

        std::array<U8, 320> transcript{};
        ST transcript_len = 0;
        auto rc = build_transcript_mac_input(client_hello, hello, transcript.data(), transcript.size(), transcript_len);
        if (!rc.ok()) {
            return rc;
        }
        rc = crypto_keyed_hash(session.keys.tx.data(), session.keys.tx.size(),
                               transcript.data(), transcript_len,
                               hello.transcript_mac.data(), hello.transcript_mac.size());
        if (!rc.ok()) {
            return rc;
        }

        std::array<U8, 192> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        rc = write_server_hello(writer, hello);
        if (!rc.ok()) {
            return rc;
        }
        return queue_packet(session.endpoint, PacketKind::Handshake, false,
                            payload.data(), writer.off,
                            session.conn_id, _stateless_seq++, nullptr,
                            SendPriority::High, session.conn_id);
    }

    Result Server::queue_internal_message(PeerSession& session, Channel channel, U8 type, const void* data, U16 len, SendPriority priority) {
        std::array<U8, NetConfig::MaxEncryptedPlaintextBytes> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_message(writer, channel, type, data, len);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_packet(session.endpoint, PacketKind::Message, true,
                          payload.data(), writer.off,
                          session.conn_id, session.send_seq++, &session.keys,
                          priority, session.conn_id);
        if (!rc.ok()) {
            return rc;
        }
        ++_stats.message_frames_sent;
        return Result::success();
    }

    Result Server::queue_message_packet(PeerSession& session, Channel channel, U8 type, const void* data, U16 len, SendPriority priority) {
        if (channel == Channel::Control) {
            return Result::fail(Errc::StateError, "control channel is reserved");
        }
        return queue_internal_message(session, channel, type, data, len, priority);
    }

    Result Server::queue_raw_payload(PeerSession& session, const U8* data, ST len, SendPriority priority) {
        return queue_packet(session.endpoint, PacketKind::Raw, true,
                            data, len,
                            session.conn_id, session.send_seq++, &session.keys,
                            priority, session.conn_id);
    }

    Result Server::queue_control_ack(PeerSession& session, Channel channel, U64 message_id) {
        std::array<U8, 16> ack_buf{};
        ByteWriter ack_writer{ ack_buf.data(), ack_buf.size() };
        auto rc = write_reliable_ack(ack_writer, channel, message_id);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_internal_message(session, Channel::Control,
                                    static_cast<U8>(ControlType::ReliableAck),
                                    ack_buf.data(), static_cast<U16>(ack_writer.off),
                                    SendPriority::High);
        if (!rc.ok()) {
            return rc;
        }
        ++_stats.reliable_acks_sent;
        return Result::success();
    }

    Result Server::queue_keepalive(PeerSession& session) {
        auto rc = queue_packet(session.endpoint, PacketKind::Keepalive, true,
                               nullptr, 0,
                               session.conn_id, session.send_seq++, &session.keys,
                               SendPriority::High, session.conn_id);
        if (rc.ok()) {
            ++_stats.keepalives_sent;
        }
        return rc;
    }

    Result Server::queue_close_packet(const Endpoint& to, U64 conn_id, CloseReason reason, bool encrypted,
                                      const SessionKeys* keys, U64 seq, SendPriority priority, U64 owner_conn_id) {
        std::array<U8, 8> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        CloseFrame close_frame{};
        close_frame.reason = reason;
        auto rc = write_close_frame(writer, close_frame);
        if (!rc.ok()) {
            return rc;
        }
        rc = queue_packet(to, PacketKind::Close, encrypted,
                          payload.data(), writer.off,
                          conn_id, seq, keys,
                          priority, owner_conn_id);
        if (rc.ok()) {
            ++_stats.closes_sent;
        }
        return rc;
    }

    Result Server::send_reliable_message(PeerSession& session, Channel channel, U8 type, const void* data, U16 len,
                                         SendPriority priority, U64 lifetime_ms) {
        const U16 max_len = static_cast<U16>(NetConfig::MaxReliableMessageBytes);
        if (len > max_len) {
            return Result::fail(Errc::TooLarge, "reliable payload exceeds inline channel budget");
        }

        ReliableSession& reliable = (channel == Channel::ReliableOrdered) ? session.ordered_reliable : session.reliable;
        PendingReliableMessage pending{};
        auto rc = reliable.enqueue(type, data, len, priority, lifetime_ms, now_ms(), pending);
        if (!rc.ok()) {
            if (rc.code == Errc::QueueFull) {
                ++_stats.queue_full_events;
            }
            return rc;
        }

        ++_stats.reliable_message_enqueued;
        rc = queue_message_packet(session, channel, type,
                                  pending.encoded_payload.data(),
                                  static_cast<U16>(pending.encoded_payload.size()),
                                  priority);
        if (!rc.ok()) {
            (void)reliable.acknowledge(pending.message_id, now_ms());
            if (rc.code == Errc::QueueFull) {
                ++_stats.backpressure_events;
            }
            return rc;
        }

        (void)reliable.note_sent(pending.message_id, now_ms());
        refresh_runtime_stats();
        return Result::success();
    }

    Result Server::send_fragmented(PeerSession& session, const SendOptions& options, U8 type, std::span<const U8> payload) {
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

        const U64 logical_message_id = session.next_fragment_message_id++;
        U64 delivery_sequence = 0;
        if (options.channel == Channel::ReliableOrdered) {
            delivery_sequence = session.next_ordered_sequence++;
        } else if (options.channel == Channel::SequencedUnreliable) {
            delivery_sequence = session.next_sequenced_sequence++;
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
                rc = send_reliable_message(session, options.channel,
                                           static_cast<U8>(ControlType::Fragment),
                                           encoded.data(), static_cast<U16>(writer.off),
                                           options.priority,
                                           options.lifetime_ms);
            } else {
                rc = queue_internal_message(session, Channel::Control,
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

    Result Server::send_payload(const Endpoint& to, U64 conn_id, const U8* data, ST len) {
        PeerSession* session = find_session(conn_id);
        if (!session || session->endpoint != to) {
            return Result::fail(Errc::Closed, "unknown peer session");
        }
        if (session->state != ConnectionState::Established) {
            return Result::fail(Errc::StateError, "peer not established");
        }
        if (len > NetConfig::MaxEncryptedPlaintextBytes) {
            return Result::fail(Errc::TooLarge, "raw payload too large");
        }
        return queue_raw_payload(*session, data, len, SendPriority::Normal);
    }

    Result Server::send_payload(const Peer& peer, const U8* data, ST len) {
        return send_payload(peer.endpoint(), peer.conn_id(), data, len);
    }

    Result Server::send_payload(const Peer& peer, std::span<const U8> payload) {
        return send_payload(peer, payload.data(), payload.size());
    }

    Result Server::send_message(const Peer& peer, Channel channel, U8 type, const void* data, U16 len) {
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "message data is null");
        }
        return send(peer, SendOptions{ channel, SendPriority::Normal, 0 }, type,
                    std::span<const U8>(static_cast<const U8*>(data), len));
    }

    Result Server::send(const Peer& peer, const SendOptions& options, U8 type, std::span<const U8> payload) {
        PeerSession* session = find_session(peer.conn_id());
        if (!session || session->endpoint != peer.endpoint()) {
            return Result::fail(Errc::Closed, "unknown peer session");
        }
        if (session->state != ConnectionState::Established) {
            return Result::fail(Errc::StateError, "peer not established");
        }
        if (!channel_is_application(options.channel)) {
            return Result::fail(Errc::InvalidArg, "send channel must be an application channel");
        }
        if (payload.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::TooLarge, "message payload too large");
        }

        auto finish = [&](Result rc) {
            if (!rc.ok() && (rc.code == Errc::QueueFull || rc.code == Errc::Backpressure)) {
                emit_backpressure(peer, options.channel, type, rc);
            }
            return rc;
        };

        const U16 len = static_cast<U16>(payload.size());
        if (len > max_inline_payload_for_channel(options.channel)) {
            return finish(send_fragmented(*session, options, type, payload));
        }

        if (options.channel == Channel::Reliable) {
            return finish(send_reliable_message(*session, Channel::Reliable, type, payload.data(), len,
                                                options.priority, options.lifetime_ms));
        }
        if (options.channel == Channel::ReliableOrdered) {
            std::array<U8, NetConfig::MaxReliableMessageBytes> ordered_payload{};
            ByteWriter writer{ ordered_payload.data(), ordered_payload.size() };
            auto rc = write_ordered_payload(writer, session->next_ordered_sequence++, payload.data(), len);
            if (!rc.ok()) {
                return rc;
            }
            return finish(send_reliable_message(*session, Channel::ReliableOrdered, type,
                                                ordered_payload.data(), static_cast<U16>(writer.off),
                                                options.priority, options.lifetime_ms));
        }
        if (options.channel == Channel::SequencedUnreliable) {
            std::array<U8, NetConfig::MaxMessageBytes> sequenced_payload{};
            ByteWriter writer{ sequenced_payload.data(), sequenced_payload.size() };
            auto rc = write_sequenced_payload(writer, session->next_sequenced_sequence++, payload.data(), len);
            if (!rc.ok()) {
                return rc;
            }
            return finish(queue_message_packet(*session, Channel::SequencedUnreliable, type,
                                               sequenced_payload.data(), static_cast<U16>(writer.off),
                                               options.priority));
        }
        return finish(queue_message_packet(*session, Channel::Unreliable, type, payload.data(), len, options.priority));
    }

    Result Server::send(const Peer& peer, Channel channel, U8 type, std::span<const U8> payload) {
        return send(peer, SendOptions{ channel, SendPriority::Normal, 0 }, type, payload);
    }

    Result Server::send_text(const Peer& peer, U8 type, std::string_view text) {
        return send_text(peer, type, text, SendOptions{ Channel::Unreliable, SendPriority::Normal, 0 });
    }

    Result Server::send_text(const Peer& peer, U8 type, std::string_view text, const SendOptions& options) {
        if (text.size() > static_cast<ST>(std::numeric_limits<U16>::max())) {
            return Result::fail(Errc::TooLarge, "text payload too large");
        }
        return send(peer, options, type,
                    std::span<const U8>(reinterpret_cast<const U8*>(text.data()), text.size()));
    }


    Result Server::send_unreliable(const Peer& peer, U8 type, std::span<const U8> payload, SendPriority priority) {
        return send(peer, SendOptions{ Channel::Unreliable, priority, 0 }, type, payload);
    }

    Result Server::send_reliable(const Peer& peer, U8 type, std::span<const U8> payload, SendPriority priority, U64 lifetime_ms) {
        return send(peer, SendOptions{ Channel::Reliable, priority, lifetime_ms }, type, payload);
    }

    Result Server::send_ordered(const Peer& peer, U8 type, std::span<const U8> payload, SendPriority priority, U64 lifetime_ms) {
        return send(peer, SendOptions{ Channel::ReliableOrdered, priority, lifetime_ms }, type, payload);
    }

    Result Server::send_latest(const Peer& peer, U8 type, std::span<const U8> payload, SendPriority priority) {
        return send(peer, SendOptions{ Channel::SequencedUnreliable, priority, 0 }, type, payload);
    }

    Result Server::send_unreliable_text(const Peer& peer, U8 type, std::string_view text, SendPriority priority) {
        return send_text(peer, type, text, SendOptions{ Channel::Unreliable, priority, 0 });
    }

    Result Server::send_reliable_text(const Peer& peer, U8 type, std::string_view text, SendPriority priority, U64 lifetime_ms) {
        return send_text(peer, type, text, SendOptions{ Channel::Reliable, priority, lifetime_ms });
    }

    Result Server::send_ordered_text(const Peer& peer, U8 type, std::string_view text, SendPriority priority, U64 lifetime_ms) {
        return send_text(peer, type, text, SendOptions{ Channel::ReliableOrdered, priority, lifetime_ms });
    }

    Result Server::send_latest_text(const Peer& peer, U8 type, std::string_view text, SendPriority priority) {
        return send_text(peer, type, text, SendOptions{ Channel::SequencedUnreliable, priority, 0 });
    }

    Result Server::broadcast(const SendOptions& options, U8 type, std::span<const U8> payload) {
        Result first_error = Result::success();
        for (auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            if (session.state != ConnectionState::Established) {
                continue;
            }
            auto rc = send(make_peer(session), options, type, payload);
            if (!rc.ok() && first_error.ok()) {
                first_error = rc;
            }
        }
        return first_error;
    }

    Result Server::broadcast_except(const Peer& excluded, const SendOptions& options, U8 type, std::span<const U8> payload) {
        Result first_error = Result::success();
        for (auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            if (session.state != ConnectionState::Established || session.conn_id == excluded.conn_id()) {
                continue;
            }
            auto rc = send(make_peer(session), options, type, payload);
            if (!rc.ok() && first_error.ok()) {
                first_error = rc;
            }
        }
        return first_error;
    }

    Result Server::broadcast_unreliable(U8 type, std::span<const U8> payload, SendPriority priority) {
        return broadcast(SendOptions{ Channel::Unreliable, priority, 0 }, type, payload);
    }

    Result Server::broadcast_reliable(U8 type, std::span<const U8> payload, SendPriority priority, U64 lifetime_ms) {
        return broadcast(SendOptions{ Channel::Reliable, priority, lifetime_ms }, type, payload);
    }

    Result Server::broadcast_ordered(U8 type, std::span<const U8> payload, SendPriority priority, U64 lifetime_ms) {
        return broadcast(SendOptions{ Channel::ReliableOrdered, priority, lifetime_ms }, type, payload);
    }

    Result Server::broadcast_latest(U8 type, std::span<const U8> payload, SendPriority priority) {
        return broadcast(SendOptions{ Channel::SequencedUnreliable, priority, 0 }, type, payload);
    }

    Result Server::broadcast_unreliable_text(U8 type, std::string_view text, SendPriority priority) {
        return broadcast_unreliable(type, std::span<const U8>(reinterpret_cast<const U8*>(text.data()), text.size()), priority);
    }

    Result Server::broadcast_reliable_text(U8 type, std::string_view text, SendPriority priority, U64 lifetime_ms) {
        return broadcast_reliable(type, std::span<const U8>(reinterpret_cast<const U8*>(text.data()), text.size()), priority, lifetime_ms);
    }

    Result Server::broadcast_ordered_text(U8 type, std::string_view text, SendPriority priority, U64 lifetime_ms) {
        return broadcast_ordered(type, std::span<const U8>(reinterpret_cast<const U8*>(text.data()), text.size()), priority, lifetime_ms);
    }

    Result Server::broadcast_latest_text(U8 type, std::string_view text, SendPriority priority) {
        return broadcast_latest(type, std::span<const U8>(reinterpret_cast<const U8*>(text.data()), text.size()), priority);
    }

    void Server::for_each_peer(const std::function<void(Peer)>& fn) const {
        if (!fn) {
            return;
        }
        for (const auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            if (session.state == ConnectionState::Established) {
                fn(make_peer(session));
            }
        }
    }

    Result Server::set_peer_user_data(const Peer& peer, void* data) {
        PeerSession* session = find_session(peer.conn_id());
        if (!session || session->endpoint != peer.endpoint()) {
            return Result::fail(Errc::Closed, "unknown peer session");
        }
        session->user_data = data;
        return Result::success();
    }

    void* Server::peer_user_data(const Peer& peer) const {
        const PeerSession* session = find_session(peer.conn_id());
        if (!session || session->endpoint != peer.endpoint()) {
            return nullptr;
        }
        return session->user_data;
    }

    Result Server::close_peer(const Peer& peer, CloseReason reason) {
        PeerSession* session = find_session(peer.conn_id());
        if (!session || session->endpoint != peer.endpoint()) {
            return Result::fail(Errc::Closed, "unknown peer session");
        }
        close_session(*session, reason, true);
        return Result::success();
    }

    ResultT<Endpoint> Server::local_endpoint() const {
        Endpoint endpoint{};
        auto rc = local_endpoint(endpoint);
        if (!rc.ok()) {
            return ResultT<Endpoint>::fail(rc.code, rc.msg);
        }
        return ResultT<Endpoint>::success(endpoint);
    }

    void Server::refill_send_budget(PeerSession& session, U64 now) {
        if (session.last_budget_refill_ms == 0) {
            session.last_budget_refill_ms = now;
            if (session.send_budget_bytes == 0) {
                session.send_budget_bytes = session.congestion.rate_bytes_per_second();
            }
            return;
        }
        if (now <= session.last_budget_refill_ms) {
            return;
        }
        const U64 elapsed_ms = now - session.last_budget_refill_ms;
        const U64 refill = (session.congestion.rate_bytes_per_second() * elapsed_ms) / 1000;
        if (refill > 0) {
            const U64 max_bucket = session.congestion.bucket_cap_bytes();
            session.send_budget_bytes = (std::min<U64>)(max_bucket, session.send_budget_bytes + refill);
            session.last_budget_refill_ms = now;
            ++_stats.send_budget_refills;
        }
    }

    Result Server::flush_pending() {
        for (;;) {
            const U64 now = now_ms();
            bool progressed = false;
            bool budget_blocked = false;

            for (auto it = _pending.begin(); it != _pending.end();) {
                PeerSession* owner = nullptr;
                if (it->owner_conn_id != 0) {
                    owner = find_session(it->owner_conn_id);
                    if (!owner) {
                        _pending_bytes -= it->len;
                        it = _pending.erase(it);
                        refresh_runtime_stats();
                        progressed = true;
                        break;
                    }
                    refill_send_budget(*owner, now);
                    if (owner->send_budget_bytes < static_cast<U64>(it->len)) {
                        budget_blocked = true;
                        owner->congestion.on_backpressure(now);
                        owner->send_budget_bytes = (std::min<U64>)(owner->send_budget_bytes, owner->congestion.bucket_cap_bytes());
                        ++it;
                        continue;
                    }
                }

                PacketView packet{};
                if (_config.enable_packet_debug_dumps && parse_packet(it->bytes.data(), it->len, packet).ok()) {
                    emit_packet_debug("send", it->to, packet);
                }

                auto rc = _sock.send_to(it->to, it->bytes.data(), it->len);
                if (!rc.ok()) {
                    if (rc.code == Errc::WouldBlock) {
                        ++_stats.would_block_events;
                        if (owner) {
                            owner->congestion.on_backpressure(now);
                            owner->send_budget_bytes = (std::min<U64>)(owner->send_budget_bytes, owner->congestion.bucket_cap_bytes());
                        }
                        if (budget_blocked) {
                            ++_stats.backpressure_events;
                        }
                        refresh_runtime_stats();
                        return Result::success();
                    }
                    ++_stats.socket_errors;
                    return rc;
                }

                if (owner) {
                    owner->send_budget_bytes -= static_cast<U64>(it->len);
                    owner->last_send_ms = now;
                    if (owner->state != ConnectionState::Established) {
                        note_preauth_send(owner->endpoint, static_cast<U64>(it->len), now);
                    }
                } else {
                    note_preauth_send(it->to, static_cast<U64>(it->len), now);
                }

                ++_stats.packets_sent;
                _stats.bytes_sent += static_cast<U64>(it->len);
                _pending_bytes -= it->len;
                it = _pending.erase(it);
                refresh_runtime_stats();
                progressed = true;
                break;
            }

            if (!progressed) {
                if (budget_blocked) {
                    ++_stats.send_budget_throttles;
                    ++_stats.backpressure_events;
                }
                refresh_runtime_stats();
                return Result::success();
            }
        }
    }

    Result Server::pump_reliable() {
        const U64 now = now_ms();
        for (auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            if (session.state != ConnectionState::Established) {
                continue;
            }

            const U64 before_retransmits = session.reliable.retransmit_events() + session.ordered_reliable.retransmit_events();
            const U64 before_losses = session.reliable.loss_events() + session.ordered_reliable.loss_events();

            const U32 expired_unordered = session.reliable.expire_old(now);
            const U32 expired_ordered = session.ordered_reliable.expire_old(now);
            if (expired_unordered > 0 || expired_ordered > 0) {
                _stats.reliable_expired += expired_unordered + expired_ordered;
                _stats.reliable_messages_dropped += expired_unordered + expired_ordered;
                _stats.ordered_messages_dropped += expired_ordered;
            }

            auto resend_due = [&](ReliableSession& reliable, Channel channel) -> Result {
                return reliable.resend_due(now, [&](PendingReliableMessage& pending) {
                    auto rc = queue_message_packet(session,
                                                   channel,
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

            auto rc = resend_due(session.reliable, Channel::Reliable);
            if (!rc.ok() && rc.code != Errc::Backpressure) {
                return rc;
            }
            if (!rc.ok()) {
                ++_stats.backpressure_events;
            }

            rc = resend_due(session.ordered_reliable, Channel::ReliableOrdered);
            if (!rc.ok() && rc.code != Errc::Backpressure) {
                return rc;
            }
            if (!rc.ok()) {
                ++_stats.backpressure_events;
            }

            const U64 after_retransmits = session.reliable.retransmit_events() + session.ordered_reliable.retransmit_events();
            const U64 after_losses = session.reliable.loss_events() + session.ordered_reliable.loss_events();
            if (after_retransmits > before_retransmits) {
                _stats.reliable_retransmits += after_retransmits - before_retransmits;
            }
            if (after_losses > before_losses) {
                const U64 losses = after_losses - before_losses;
                _stats.reliable_loss_events += losses;
                session.congestion.on_loss(now, losses);
                session.send_budget_bytes = (std::min<U64>)(session.send_budget_bytes, session.congestion.bucket_cap_bytes());
            }
        }
        refresh_runtime_stats();
        return Result::success();
    }

    void Server::emit_message(const Peer& peer, const MsgView& msg) {
        auto text = _text_handlers.find(msg.type);
        if (text != _text_handlers.end() && text->second) {
            text->second(peer, msg.text());
        }
        auto binary = _binary_handlers.find(msg.type);
        if (binary != _binary_handlers.end() && binary->second) {
            binary->second(peer, msg);
        }
        if (_on_message) {
            _on_message(peer, msg);
        }
    }

    Result Server::deliver_application_message(PeerSession& session, Channel channel, U8 type, const U8* data, U16 len, U64 delivery_sequence) {
        Peer peer = make_peer(session);

        if (channel == Channel::ReliableOrdered) {
            ++_stats.ordered_messages_received;
            U64 released = 0;
            bool buffered = false;
            bool stale = false;
            auto rc = session.ordered.accept(delivery_sequence, type, data, len,
                                             [&](U8 delivered_type, const U8* delivered_data, U16 delivered_len) {
                                                 ++released;
                                                 MsgView delivered{};
                                                 delivered.channel = Channel::ReliableOrdered;
                                                 delivered.type = delivered_type;
                                                 delivered.data = delivered_data;
                                                 delivered.len = delivered_len;
                                                 emit_message(peer, delivered);
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
            _stats.ordered_messages_released += released;
            return Result::success();
        }

        if (channel == Channel::SequencedUnreliable) {
            ++_stats.sequenced_messages_received;
            if (!session.sequenced.accept(delivery_sequence)) {
                ++_stats.sequenced_messages_dropped;
                return Result::success();
            }
            MsgView delivered{};
            delivered.channel = Channel::SequencedUnreliable;
            delivered.type = type;
            delivered.data = data;
            delivered.len = len;
            emit_message(peer, delivered);
            return Result::success();
        }

        MsgView delivered{};
        delivered.channel = channel;
        delivered.type = type;
        delivered.data = data;
        delivered.len = len;
        emit_message(peer, delivered);
        return Result::success();
    }

    Result Server::deliver_reassembled_message(PeerSession& session, const FragmentedMessage& message) {
        ++_stats.fragmented_messages_received;
        return deliver_application_message(session,
                                           message.channel,
                                           message.type,
                                           message.payload.empty() ? nullptr : message.payload.data(),
                                           static_cast<U16>(message.payload.size()),
                                           message.delivery_sequence);
    }

    Result Server::handle_fragment_payload(PeerSession& session, const FragmentView& fragment) {
        if (!session.reassembler.contains(fragment.message_id) &&
            (total_reassembly_memory_bytes() + fragment.original_length) > _config.abuse.max_total_reassembly_memory_server) {
            ++_stats.reassembly_memory_rejections;
            ++_stats.reassembly_drops;
            return Result::success();
        }

        bool duplicate = false;
        bool completed = false;
        auto rc = session.reassembler.accept(now_ms(), fragment,
                                             [&](const FragmentedMessage& message) {
                                                 return deliver_reassembled_message(session, message);
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

    void Server::dispatch_message_frame(PeerSession& session, const MsgView& msg) {
        if (msg.channel == Channel::Control) {
            if (msg.type == static_cast<U8>(ControlType::ReliableAck)) {
                ByteReader ack_reader{ msg.data, static_cast<ST>(msg.len) };
                Channel ack_channel = Channel::Reliable;
                U64 acked_message_id = 0;
                auto rc = read_reliable_ack(ack_reader, ack_channel, acked_message_id);
                if (!rc.ok()) {
                    ++_stats.bad_packets;
                    close_session(session, CloseReason::InvalidPacket, true);
                    return;
                }
                ReliableSession& reliable = (ack_channel == Channel::ReliableOrdered)
                    ? session.ordered_reliable
                    : session.reliable;
                const U64 ack_now = now_ms();
                const ReliableAckEvent ack = reliable.acknowledge(acked_message_id, ack_now);
                if (ack.removed) {
                    ++_stats.reliable_acks_received;
                    session.congestion.on_ack(ack.rtt_sample_valid, ack.rtt_sample_ms, ack.retransmitted, ack_now);
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
                    close_session(session, CloseReason::InvalidPacket, true);
                    return;
                }
                ++_stats.fragments_received;
                rc = handle_fragment_payload(session, fragment);
                if (!rc.ok()) {
                    ++_stats.bad_packets;
                    close_session(session, CloseReason::InvalidPacket, true);
                }
                return;
            }

            ++_stats.protocol_errors;
            close_session(session, CloseReason::ProtocolError, true);
            return;
        }

        if (msg.channel == Channel::Reliable || msg.channel == Channel::ReliableOrdered) {
            ByteReader reliable_reader{ msg.data, static_cast<ST>(msg.len) };
            ReliablePayloadView reliable{};
            auto rc = read_reliable_payload(reliable_reader, reliable);
            if (!rc.ok()) {
                ++_stats.bad_packets;
                close_session(session, CloseReason::InvalidPacket, true);
                return;
            }

            (void)queue_control_ack(session, msg.channel, reliable.message_id);
            ReliableSession& inbound = (msg.channel == Channel::ReliableOrdered)
                ? session.ordered_reliable
                : session.reliable;
            if (!inbound.accept_incoming(reliable.message_id)) {
                return;
            }

            ++_stats.reliable_messages_delivered;
            if (msg.type == static_cast<U8>(ControlType::Fragment)) {
                ByteReader fragment_reader{ reliable.data, static_cast<ST>(reliable.len) };
                FragmentView fragment{};
                auto fragment_rc = read_fragment_payload(fragment_reader, fragment);
                if (fragment_rc.ok()) {
                    ++_stats.fragments_received;
                    rc = handle_fragment_payload(session, fragment);
                    if (!rc.ok()) {
                        ++_stats.bad_packets;
                        close_session(session, CloseReason::InvalidPacket, true);
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
                    close_session(session, CloseReason::InvalidPacket, true);
                    return;
                }
                rc = deliver_application_message(session, Channel::ReliableOrdered,
                                                 msg.type, ordered.data, ordered.len,
                                                 ordered.delivery_sequence);
                if (!rc.ok()) {
                    ++_stats.protocol_errors;
                    close_session(session, CloseReason::ProtocolError, true);
                }
                return;
            }

            rc = deliver_application_message(session, Channel::Reliable,
                                             msg.type, reliable.data, reliable.len, 0);
            if (!rc.ok()) {
                ++_stats.protocol_errors;
                close_session(session, CloseReason::ProtocolError, true);
            }
            return;
        }

        if (msg.channel == Channel::SequencedUnreliable) {
            ByteReader sequenced_reader{ msg.data, static_cast<ST>(msg.len) };
            SequencedPayloadView sequenced{};
            auto rc = read_sequenced_payload(sequenced_reader, sequenced);
            if (!rc.ok()) {
                ++_stats.bad_packets;
                close_session(session, CloseReason::InvalidPacket, true);
                return;
            }
            rc = deliver_application_message(session, Channel::SequencedUnreliable,
                                             msg.type, sequenced.data, sequenced.len,
                                             sequenced.delivery_sequence);
            if (!rc.ok()) {
                ++_stats.protocol_errors;
                close_session(session, CloseReason::ProtocolError, true);
            }
            return;
        }

        auto rc = deliver_application_message(session, msg.channel, msg.type, msg.data, msg.len, 0);
        if (!rc.ok()) {
            ++_stats.protocol_errors;
            close_session(session, CloseReason::ProtocolError, true);
        }
    }

    void Server::dispatch_message_payload(PeerSession& session, const U8* payload, ST payload_len) {
        ByteReader reader{ payload, payload_len };
        for (;;) {
            MsgView msg{};
            auto rc = read_message(reader, msg);
            if (rc.code == Errc::EndOfStream) {
                break;
            }
            if (!rc.ok()) {
                ++_stats.bad_packets;
                close_session(session, CloseReason::InvalidPacket, true);
                return;
            }
            ++_stats.message_frames_received;
            dispatch_message_frame(session, msg);
            if (session.state == ConnectionState::Closed) {
                return;
            }
        }
    }

    Result Server::handle_client_hello(const Endpoint& from, const ClientHello& hello, ST) {
        const U64 now = now_ms();
        if (hello.has_retry_token && hello.has_resumption_token) {
            return Result::fail(Errc::BadPacket, "client hello cannot include both retry and resumption token");
        }
        if (endpoint_is_banned(from, now)) {
            ++_stats.dropped_packets;
            return Result::success();
        }
        if (endpoint_rate_limited(from, now)) {
            return Result::success();
        }

        bool resumed_without_retry = false;
        if (_config.enable_session_resumption && hello.has_resumption_token && !hello.has_retry_token) {
            ++_stats.session_resumptions_attempted;
            const auto resume_rc = validate_resumption_token(from, hello.resumption_token, now);
            if (resume_rc.ok()) {
                resumed_without_retry = true;
                ++_stats.session_resumptions_accepted;
            } else {
                ++_stats.session_resumptions_rejected;
            }
        }

        if (!resumed_without_retry) {
            if (!hello.has_retry_token) {
                return queue_retry(from, make_retry_token(from, hello, now));
            }

            auto token_rc = validate_retry_token(from, hello, hello.retry_token, now);
            if (!token_rc.ok()) {
                if (token_rc.code == Errc::Timeout) {
                    (void)queue_close_packet(from, 0, CloseReason::CookieExpired,
                                             false, nullptr, _stateless_seq++, SendPriority::High, 0);
                } else {
                    (void)queue_retry(from, make_retry_token(from, hello, now));
                }
                return Result::success();
            }
        }

        evict_stale_sessions();
        if (_sessions.size() >= _config.max_peer_sessions) {
            ++_stats.dropped_packets;
            (void)queue_close_packet(from, 0, CloseReason::Backpressure,
                                     false, nullptr, _stateless_seq++, SendPriority::High, 0);
            return Result::success();
        }

        const std::string host_key = endpoint_host_key(from);
        U32 sessions_for_host = 0;
        for (const auto& [existing_conn_id, existing_session] : _sessions) {
            (void)existing_conn_id;
            if (endpoint_host_key(existing_session.endpoint) == host_key) {
                ++sessions_for_host;
            }
        }
        if (sessions_for_host >= _config.abuse.max_sessions_per_ip) {
            ++_stats.rate_limited_packets;
            ++_stats.dropped_packets;
            (void)queue_close_packet(from, 0, CloseReason::RateLimited,
                                     false, nullptr, _stateless_seq++, SendPriority::High, 0);
            return Result::success();
        }

        if (auto* existing = find_session_by_endpoint(from)) {
            evict_session(existing->conn_id);
        }

        PeerSession session{};
        session.endpoint = from;
        session.conn_id = allocate_conn_id();
        session.peer_id = _next_peer_id++;
        if (_next_peer_id == 0) {
            _next_peer_id = 1;
        }
        session.state = ConnectionState::Idle;
        session.close_reason = CloseReason::Normal;
        session.created_ms = now;
        session.last_recv_ms = now;
        session.last_send_ms = 0;
        session.send_seq = 1;
        session.congestion.configure(_config.congestion, _config.send_budget_bytes_per_second);
        session.send_budget_bytes = session.congestion.rate_bytes_per_second();
        session.last_budget_refill_ms = now;
        session.next_fragment_message_id = 1;
        session.next_ordered_sequence = 1;
        session.next_sequenced_sequence = 1;
        session.client_nonce = hello.client_nonce;
        session.client_public_key = hello.client_public_key;
        session.handshake_had_retry_token = !resumed_without_retry && hello.has_retry_token;
        if (session.handshake_had_retry_token) {
            session.handshake_retry_token = hello.retry_token;
        }
        session.handshake_had_resumption_token = resumed_without_retry && hello.has_resumption_token;
        if (session.handshake_had_resumption_token) {
            session.handshake_resumption_token = hello.resumption_token;
        }
        crypto_random_bytes(session.server_nonce.data(), session.server_nonce.size());

        ReliabilityConfig reliability = _config.reliability;
        reliability.max_pending_bytes = (std::min<U32>)(reliability.max_pending_bytes,
                                                      _config.abuse.max_queued_reliable_bytes_per_peer);
        session.reliable.configure(reliability);
        session.ordered_reliable.configure(reliability);
        session.ordered.set_max_buffered(_config.reliability.ordered_receive_window);
        session.reassembler.configure(_config.fragmentation);

        auto rc = crypto_generate_keypair(session.ephemeral);
        if (!rc.ok()) {
            return rc;
        }
        rc = crypto_derive_server_session_keys(session.ephemeral,
                                               session.client_public_key.data(), session.client_public_key.size(),
                                               session.keys);
        if (!rc.ok()) {
            session.ephemeral.clear();
            return rc;
        }
        crypto_secure_zero(session.ephemeral.secret_key.data(), session.ephemeral.secret_key.size());
        transition_state(session, ConnectionState::Handshaking);

        const U64 conn_id = session.conn_id;
        _endpoint_to_conn[from] = conn_id;
        _sessions.emplace(conn_id, std::move(session));
        refresh_runtime_stats();

        PeerSession* stored = find_session(conn_id);
        if (!stored) {
            return Result::fail(Errc::Internal, "session insertion failed");
        }
        rc = queue_server_hello(*stored);
        if (!rc.ok()) {
            evict_session(conn_id);
            return rc;
        }
        return Result::success();
    }

    Result Server::handle_handshake_packet(const Endpoint& from, const PacketView& packet, ST wire_len) {
        if (packet_header_encrypted(packet.h)) {
            return Result::fail(Errc::ProtocolError, "encrypted handshake packet is illegal");
        }
        if (!packet.payload || packet.h.payload_len == 0) {
            return Result::fail(Errc::BadPacket, "empty handshake packet");
        }

        ByteReader reader{ packet.payload, static_cast<ST>(packet.h.payload_len) };
        ClientHello hello{};
        auto rc = read_client_hello(reader, hello);
        if (!rc.ok()) {
            return rc;
        }
        if (packet.h.conn_id != 0) {
            return Result::fail(Errc::ProtocolError, "client hello must use conn_id 0");
        }
        return handle_client_hello(from, hello, wire_len);
    }

    Result Server::handle_session_packet(PeerSession& session, const PacketView& packet) {
        if (static_cast<PacketKind>(packet.h.kind) == PacketKind::Handshake) {
            return Result::fail(Errc::ProtocolError, "handshake packet not allowed for session");
        }
        if (!packet_header_encrypted(packet.h)) {
            return Result::fail(Errc::ProtocolError, "unencrypted secure packet");
        }
        if (packet.h.conn_id != session.conn_id) {
            return Result::fail(Errc::ProtocolError, "connection id mismatch");
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
        rc = crypto_aead_decrypt(session.keys.rx.data(), session.keys.rx.size(),
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

        if (!session.packet_window.accept(packet.h.seq)) {
            ++_stats.replays_dropped;
            return Result::fail(Errc::Replay, "replayed packet");
        }

        session.last_recv_ms = now_ms();
        if (session.state == ConnectionState::Handshaking) {
            transition_state(session, ConnectionState::Established);
            ++_stats.handshake_successes;
            ++_stats.sessions_established;
        }

        PacketView logical{};
        logical.h = packet.h;
        logical.h.payload_len = static_cast<U32>(plaintext_len);
        logical.payload = (plaintext_len == 0) ? nullptr : plaintext.data();

        if (_on_packet) {
            _on_packet(session.endpoint, logical);
        }
        emit_packet_debug("recv", session.endpoint, logical);

        switch (static_cast<PacketKind>(packet.h.kind)) {
        case PacketKind::Raw:
            return Result::success();
        case PacketKind::Message:
            dispatch_message_payload(session, logical.payload, logical.h.payload_len);
            return Result::success();
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
            if (session.state != ConnectionState::Closing) {
                close_session(session, close_frame.reason, true);
            } else {
                transition_state(session, ConnectionState::Closed);
            }
            return Result::success();
        }
        case PacketKind::Handshake:
            return Result::fail(Errc::ProtocolError, "handshake packet in secure path");
        }

        return Result::fail(Errc::ProtocolError, "unknown secure packet kind");
    }

    void Server::handle_packet(const Endpoint& from, const PacketView& packet, ST wire_len) {
        const U64 now = now_ms();
        if (endpoint_is_banned(from, now)) {
            ++_stats.dropped_packets;
            return;
        }

        Result rc;
        if (static_cast<PacketKind>(packet.h.kind) == PacketKind::Handshake) {
            if (_on_packet) {
                _on_packet(from, packet);
            }
            emit_packet_debug("recv", from, packet);
            rc = handle_handshake_packet(from, packet, wire_len);
        } else {
            if (packet.h.conn_id == 0) {
                rc = Result::fail(Errc::ProtocolError, "secure packet missing conn_id");
            } else {
                PeerSession* session = find_session(packet.h.conn_id);
                if (!session || session->endpoint != from) {
                    rc = Result::fail(Errc::Closed, "unknown session");
                    (void)queue_close_packet(from, packet.h.conn_id, CloseReason::UnknownConnection,
                                             false, nullptr, _stateless_seq++, SendPriority::High, 0);
                } else {
                    rc = handle_session_packet(*session, packet);
                }
            }
        }

        if (!rc.ok()) {
            if (rc.code == Errc::Replay) {
                return;
            }
            if (rc.code == Errc::AuthFailed) {
                note_invalid_packet(from, now);
                if (auto* session = find_session(packet.h.conn_id)) {
                    close_session(*session, CloseReason::AuthenticationFailed, true);
                }
                return;
            }
            if (rc.code == Errc::StateError) {
                ++_stats.protocol_errors;
                note_invalid_packet(from, now);
                if (auto* session = find_session(packet.h.conn_id)) {
                    close_session(*session, CloseReason::StateViolation, true);
                }
                return;
            }
            if (rc.code == Errc::ProtocolError) {
                ++_stats.protocol_errors;
                note_invalid_packet(from, now);
                if (auto* session = find_session(packet.h.conn_id)) {
                    close_session(*session, CloseReason::ProtocolError, true);
                }
                return;
            }
            if (rc.code == Errc::BadPacket || rc.code == Errc::Truncated) {
                ++_stats.bad_packets;
                note_invalid_packet(from, now);
                if (packet.h.conn_id != 0) {
                    if (auto* session = find_session(packet.h.conn_id)) {
                        close_session(*session, CloseReason::InvalidPacket, true);
                    }
                }
            }
        }
    }

    void Server::close_session(PeerSession& session, CloseReason reason, bool send_close) {
        session.close_reason = reason;
        if (send_close && session.state != ConnectionState::Closed) {
            const bool encrypted = (session.state == ConnectionState::Established || session.state == ConnectionState::Closing);
            (void)queue_close_packet(session.endpoint, session.conn_id, reason,
                                     encrypted,
                                     encrypted ? &session.keys : nullptr,
                                     encrypted ? session.send_seq++ : _stateless_seq++,
                                     SendPriority::High,
                                     session.conn_id);
            transition_state(session, ConnectionState::Closing);
        } else {
            transition_state(session, ConnectionState::Closed);
        }
    }

    void Server::evict_session(U64 conn_id) {
        auto it = _sessions.find(conn_id);
        if (it == _sessions.end()) {
            return;
        }
        _endpoint_to_conn.erase(it->second.endpoint);
        it->second.keys.clear();
        it->second.ephemeral.clear();
        it->second.reliable.clear();
        it->second.ordered_reliable.clear();
        it->second.ordered.clear();
        it->second.sequenced.clear();
        it->second.reassembler.clear();
        _sessions.erase(it);
        ++_stats.peers_evicted;
        refresh_runtime_stats();
    }

    void Server::evict_stale_sessions() {
        const U64 now = now_ms();
        std::vector<U64> doomed;
        doomed.reserve(_sessions.size());
        for (const auto& [conn_id, session] : _sessions) {
            if (session.state == ConnectionState::Closed) {
                doomed.push_back(conn_id);
                continue;
            }
            if (session.state == ConnectionState::Closing && session.last_send_ms != 0 &&
                (now - session.last_send_ms) >= _config.close_drain_ms) {
                doomed.push_back(conn_id);
            }
        }
        for (U64 conn_id : doomed) {
            evict_session(conn_id);
        }
    }

    U64 Server::allocate_conn_id() {
        for (;;) {
            U64 candidate = 0;
            crypto_random_bytes(&candidate, sizeof(candidate));
            if (candidate == 0) {
                continue;
            }
            if (_sessions.find(candidate) == _sessions.end()) {
                return candidate;
            }
        }
    }

    Server::PeerSession* Server::find_session(U64 conn_id) {
        auto it = _sessions.find(conn_id);
        return (it == _sessions.end()) ? nullptr : &it->second;
    }

    const Server::PeerSession* Server::find_session(U64 conn_id) const {
        auto it = _sessions.find(conn_id);
        return (it == _sessions.end()) ? nullptr : &it->second;
    }

    Server::PeerSession* Server::find_session_by_endpoint(const Endpoint& endpoint) {
        auto it = _endpoint_to_conn.find(endpoint);
        if (it == _endpoint_to_conn.end()) {
            return nullptr;
        }
        return find_session(it->second);
    }

    Result Server::pump_receive() {
        for (;;) {
            Endpoint from{};
            ST n = 0;
            auto rc = _sock.recv_from(from, _rxbuf.data(), _rxbuf.size(), n);
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
                note_preauth_receive(from, static_cast<U64>(n), now_ms());
                if (rc.code == Errc::UnsupportedVersion) {
                    ++_stats.unsupported_version_packets;
                    (void)queue_close_packet(from, 0, CloseReason::UnsupportedVersion,
                                             false, nullptr, _stateless_seq++, SendPriority::High, 0);
                } else {
                    ++_stats.bad_packets;
                    note_invalid_packet(from, now_ms());
                }
                continue;
            }

            if (static_cast<PacketKind>(packet.h.kind) == PacketKind::Handshake || packet.h.conn_id == 0) {
                note_preauth_receive(from, static_cast<U64>(n), now_ms());
            } else {
                PeerSession* session = find_session(packet.h.conn_id);
                if (!session || session->state != ConnectionState::Established) {
                    note_preauth_receive(from, static_cast<U64>(n), now_ms());
                }
            }

            handle_packet(from, packet, n);
        }

        return Result::success();
    }

    Result Server::run_housekeeping() {
        const U64 now = now_ms();
        for (auto& [conn_id, session] : _sessions) {
            (void)conn_id;
            session.reassembler.expire_old(now, [&](U64) {
                ++_stats.reassemblies_expired;
                ++_stats.reassembly_drops;
            });

            if (session.state == ConnectionState::Handshaking && (now - session.created_ms) > _config.handshake_timeout_ms) {
                ++_stats.establish_timeouts;
                close_session(session, CloseReason::EstablishTimeout, true);
                continue;
            }
            if (session.state == ConnectionState::Established) {
                if (session.last_recv_ms != 0 && (now - session.last_recv_ms) > _config.idle_timeout_ms) {
                    ++_stats.idle_timeouts;
                    close_session(session, CloseReason::IdleTimeout, true);
                    continue;
                }
                if (session.last_send_ms == 0 || (now - session.last_send_ms) >= _config.keepalive_interval_ms) {
                    auto rc = queue_keepalive(session);
                    if (!rc.ok()) {
                        return rc;
                    }
                }
            }
            if (session.state == ConnectionState::Closing && session.last_send_ms != 0 &&
                (now - session.last_send_ms) >= _config.close_drain_ms) {
                transition_state(session, ConnectionState::Closed);
            }
        }

        for (auto it = _preauth.begin(); it != _preauth.end();) {
            if (now < it->second.last_seen_ms || (now - it->second.last_seen_ms) <= _config.idle_timeout_ms) {
                ++it;
                continue;
            }
            it = _preauth.erase(it);
        }
        for (auto it = _ip_abuse.begin(); it != _ip_abuse.end();) {
            if (it->second.banned_until_ms > now) {
                ++it;
                continue;
            }
            const bool idle_window = (it->second.window_started_ms == 0) || ((now - it->second.window_started_ms) > 5000);
            if (idle_window && it->second.handshakes_in_window == 0 && it->second.invalid_penalty_score == 0) {
                it = _ip_abuse.erase(it);
            } else {
                ++it;
            }
        }

        evict_stale_sessions();
        refresh_runtime_stats();
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
        rc = pump_receive();
        if (!rc.ok()) {
            return rc;
        }
        return run_housekeeping();
    }

    Result Server::context_poll() {
        return tick();
    }

    Result Server::local_endpoint(Endpoint& out) const {
        return _sock.local_endpoint(out);
    }

} // namespace scn
