#pragma once

#include <algorithm>
#include <cstddef>

#include "securecnet/result.hpp"
#include "securecnet/util/util.h"

namespace scn {

    enum class SendPriority : U8 {
        Low = 0,
        Normal = 1,
        High = 2,
    };

    struct NetConfig {
        // Conservative UDP payload budget after IP/UDP overhead.
        static constexpr ST MaxPacketBytes = 1300;
        static constexpr ST PacketHeaderBytes = 28;
        static constexpr ST MaxPayloadBytes = MaxPacketBytes - PacketHeaderBytes;

        static constexpr ST AeadKeyBytes = 32;
        static constexpr ST AeadNonceBytes = 24;
        static constexpr ST AeadTagBytes = 16;
        static constexpr ST KeyExchangePublicKeyBytes = 32;
        static constexpr ST KeyExchangeSecretKeyBytes = 32;
        static constexpr ST SessionKeyBytes = 32;
        static constexpr ST ClientNonceBytes = 16;
        static constexpr ST ServerNonceBytes = 16;
        static constexpr ST RetryTokenMacBytes = 16;
        static constexpr ST ResumptionTokenMacBytes = 16;
        static constexpr ST CookieSecretBytes = 32;
        static constexpr ST TranscriptMacBytes = 16;

        // Message framing lives inside encrypted/plain payloads.
        static constexpr ST MessageHeaderBytes = 4;
        static constexpr ST MaxEncryptedPlaintextBytes = MaxPayloadBytes - AeadTagBytes;
        static constexpr ST MaxMessageBytes = MaxEncryptedPlaintextBytes - MessageHeaderBytes;

        // Delivery mode envelopes.
        static constexpr ST ReliableEnvelopeBytes = 8;
        static constexpr ST OrderedEnvelopeBytes = 8;
        static constexpr ST SequencedEnvelopeBytes = 8;
        static constexpr ST MaxReliableMessageBytes = MaxMessageBytes - ReliableEnvelopeBytes;
        static constexpr ST MaxOrderedMessageBytes = MaxReliableMessageBytes - OrderedEnvelopeBytes;
        static constexpr ST MaxSequencedMessageBytes = MaxMessageBytes - SequencedEnvelopeBytes;

        // Fragment header: message_id + delivery_sequence + channel + type + index + count + original_length.
        static constexpr ST FragmentHeaderBytes = 24;
        static constexpr ST MaxFragmentDataBytes = MaxOrderedMessageBytes - FragmentHeaderBytes;

        static constexpr ST MaxPendingPackets = 256;
        static constexpr ST MaxPendingReliableMessages = 256;

        static constexpr U64 HandshakeTimeoutMs = 5000;
        static constexpr U64 IdleTimeoutMs = 15000;
        static constexpr U64 KeepaliveIntervalMs = 5000;
        static constexpr U64 RetryTokenLifetimeMs = 1500;
        static constexpr U64 ResumptionTokenLifetimeMs = 60000;
        static constexpr U64 CloseDrainMs = 250;
        static constexpr ST MaxPeerSessions = 1024;

        static constexpr U16 ProtocolVersion = 3;
        static constexpr U32 Magic = 0x53434E33; // "SCN3"
    };

    static_assert(NetConfig::MaxPacketBytes > NetConfig::PacketHeaderBytes,
                  "MaxPacketBytes must be larger than PacketHeaderBytes");
    static_assert(NetConfig::MaxPayloadBytes > NetConfig::AeadTagBytes,
                  "MaxPayloadBytes must be larger than AEAD tag bytes");
    static_assert(NetConfig::MaxEncryptedPlaintextBytes > NetConfig::MessageHeaderBytes,
                  "Encrypted plaintext budget must hold at least one message header");
    static_assert(NetConfig::MaxMessageBytes > NetConfig::ReliableEnvelopeBytes,
                  "MaxMessageBytes must be larger than ReliableEnvelopeBytes");
    static_assert(NetConfig::MaxReliableMessageBytes > NetConfig::OrderedEnvelopeBytes,
                  "MaxReliableMessageBytes must be larger than OrderedEnvelopeBytes");
    static_assert(NetConfig::MaxOrderedMessageBytes > NetConfig::FragmentHeaderBytes,
                  "MaxOrderedMessageBytes must be larger than FragmentHeaderBytes");

    struct ReliabilityConfig {
        U64 initial_rto_ms{ 120 };
        U64 min_rto_ms{ 40 };
        U64 max_rto_ms{ 2000 };
        U32 max_pending_messages{ static_cast<U32>(NetConfig::MaxPendingReliableMessages) };
        U32 max_pending_bytes{ 64 * 1024 };
        U32 max_inflight_messages{ 32 };
        U32 ordered_receive_window{ 64 };
    };

    struct FragmentationConfig {
        bool enabled{ true };
        U16 max_fragments_per_message{ 64 };
        U32 max_reassembled_message_bytes{ 16 * 1024 };
        U32 max_concurrent_reassemblies_per_peer{ 32 };
        U64 max_total_reassembly_memory_per_peer{ 128 * 1024 };
        U64 reassembly_timeout_ms{ 1500 };
    };

    struct AbuseConfig {
        U32 per_ip_handshake_rate_limit_per_second{ 64 };
        U32 invalid_packet_ban_threshold{ 16 };
        U64 invalid_packet_ban_ms{ 5000 };
        U32 max_sessions_per_ip{ 64 };
        U32 anti_amplification_factor{ 3 };
        U32 anti_amplification_slack_bytes{ 256 };
        U32 max_queued_reliable_bytes_per_peer{ 64 * 1024 };
        U64 max_total_reassembly_memory_server{ 4 * 1024 * 1024 };
    };

    struct ClientConfig {
        ReliabilityConfig reliability{};
        FragmentationConfig fragmentation{};
        U64 handshake_timeout_ms{ NetConfig::HandshakeTimeoutMs };
        U64 idle_timeout_ms{ NetConfig::IdleTimeoutMs };
        U64 keepalive_interval_ms{ NetConfig::KeepaliveIntervalMs };
        U64 close_drain_ms{ NetConfig::CloseDrainMs };
        U32 max_pending_packets{ static_cast<U32>(NetConfig::MaxPendingPackets) };
        U32 send_budget_bytes_per_second{ 128 * 1024 };
        bool enable_session_resumption{ true };
        bool enable_packet_debug_dumps{ false };
        bool single_threaded_event_loop{ true };
    };

    struct ServerConfig {
        ReliabilityConfig reliability{};
        FragmentationConfig fragmentation{};
        AbuseConfig abuse{};
        U64 handshake_timeout_ms{ NetConfig::HandshakeTimeoutMs };
        U64 idle_timeout_ms{ NetConfig::IdleTimeoutMs };
        U64 keepalive_interval_ms{ NetConfig::KeepaliveIntervalMs };
        U64 close_drain_ms{ NetConfig::CloseDrainMs };
        U32 max_pending_packets{ static_cast<U32>(NetConfig::MaxPendingPackets) };
        U32 send_budget_bytes_per_second{ 256 * 1024 };
        ST max_peer_sessions{ NetConfig::MaxPeerSessions };
        bool enable_session_resumption{ true };
        bool enable_packet_debug_dumps{ false };
        bool single_threaded_event_loop{ true };
    };

    inline Result validate_reliability_config(const ReliabilityConfig& cfg) {
        if (cfg.initial_rto_ms == 0 || cfg.min_rto_ms == 0 || cfg.max_rto_ms == 0) {
            return Result::fail(Errc::InvalidArg, "reliability timeout values must be non-zero");
        }
        if (cfg.min_rto_ms > cfg.initial_rto_ms || cfg.initial_rto_ms > cfg.max_rto_ms) {
            return Result::fail(Errc::InvalidArg, "reliability timeout values are inconsistent");
        }
        if (cfg.max_pending_messages == 0 || cfg.max_inflight_messages == 0) {
            return Result::fail(Errc::InvalidArg, "reliability queue limits must be non-zero");
        }
        if (cfg.max_pending_bytes < NetConfig::MaxReliableMessageBytes) {
            return Result::fail(Errc::InvalidArg, "reliability byte budget is too small");
        }
        if (cfg.ordered_receive_window == 0) {
            return Result::fail(Errc::InvalidArg, "ordered receive window must be non-zero");
        }
        return Result::success();
    }

    inline Result validate_fragmentation_config(const FragmentationConfig& cfg) {
        if (!cfg.enabled) {
            return Result::success();
        }
        if (cfg.max_fragments_per_message == 0) {
            return Result::fail(Errc::InvalidArg, "fragment count limit must be non-zero");
        }
        if (cfg.max_reassembled_message_bytes == 0 || cfg.max_reassembled_message_bytes > U16_MAX) {
            return Result::fail(Errc::InvalidArg, "reassembled message size must fit in wire format");
        }
        const U32 required_fragments = static_cast<U32>((cfg.max_reassembled_message_bytes + NetConfig::MaxFragmentDataBytes - 1) /
                                                        NetConfig::MaxFragmentDataBytes);
        if (required_fragments > cfg.max_fragments_per_message) {
            return Result::fail(Errc::InvalidArg, "fragment count limit is too small for max_reassembled_message_bytes");
        }
        if (cfg.max_concurrent_reassemblies_per_peer == 0) {
            return Result::fail(Errc::InvalidArg, "concurrent reassembly limit must be non-zero");
        }
        if (cfg.max_total_reassembly_memory_per_peer < cfg.max_reassembled_message_bytes) {
            return Result::fail(Errc::InvalidArg, "reassembly memory budget must hold at least one message");
        }
        if (cfg.reassembly_timeout_ms == 0) {
            return Result::fail(Errc::InvalidArg, "reassembly timeout must be non-zero");
        }
        return Result::success();
    }

    inline Result validate_client_config(const ClientConfig& cfg) {
        auto rc = validate_reliability_config(cfg.reliability);
        if (!rc.ok()) {
            return rc;
        }
        rc = validate_fragmentation_config(cfg.fragmentation);
        if (!rc.ok()) {
            return rc;
        }
        if (cfg.handshake_timeout_ms == 0 || cfg.idle_timeout_ms == 0 || cfg.close_drain_ms == 0) {
            return Result::fail(Errc::InvalidArg, "client timeout values must be non-zero");
        }
        if (cfg.keepalive_interval_ms == 0 || cfg.keepalive_interval_ms >= cfg.idle_timeout_ms) {
            return Result::fail(Errc::InvalidArg, "client keepalive must be non-zero and less than idle timeout");
        }
        if (cfg.max_pending_packets == 0) {
            return Result::fail(Errc::InvalidArg, "client pending packet limit must be non-zero");
        }
        if (cfg.send_budget_bytes_per_second == 0) {
            return Result::fail(Errc::InvalidArg, "client send budget must be non-zero");
        }
        return Result::success();
    }

    inline Result validate_server_config(const ServerConfig& cfg) {
        auto rc = validate_reliability_config(cfg.reliability);
        if (!rc.ok()) {
            return rc;
        }
        rc = validate_fragmentation_config(cfg.fragmentation);
        if (!rc.ok()) {
            return rc;
        }
        if (cfg.handshake_timeout_ms == 0 || cfg.idle_timeout_ms == 0 || cfg.close_drain_ms == 0) {
            return Result::fail(Errc::InvalidArg, "server timeout values must be non-zero");
        }
        if (cfg.keepalive_interval_ms == 0 || cfg.keepalive_interval_ms >= cfg.idle_timeout_ms) {
            return Result::fail(Errc::InvalidArg, "server keepalive must be non-zero and less than idle timeout");
        }
        if (cfg.max_pending_packets == 0 || cfg.max_peer_sessions == 0) {
            return Result::fail(Errc::InvalidArg, "server queue/session limits must be non-zero");
        }
        if (cfg.send_budget_bytes_per_second == 0) {
            return Result::fail(Errc::InvalidArg, "server send budget must be non-zero");
        }
        if (cfg.abuse.per_ip_handshake_rate_limit_per_second == 0 ||
            cfg.abuse.max_sessions_per_ip == 0 ||
            cfg.abuse.anti_amplification_factor == 0 ||
            cfg.abuse.max_queued_reliable_bytes_per_peer == 0 ||
            cfg.abuse.max_total_reassembly_memory_server == 0) {
            return Result::fail(Errc::InvalidArg, "server abuse limits must be non-zero");
        }
        if (cfg.abuse.max_queued_reliable_bytes_per_peer < cfg.reliability.max_pending_bytes) {
            return Result::fail(Errc::InvalidArg, "server reliable byte quota must cover reliability.max_pending_bytes");
        }
        if (cfg.abuse.max_total_reassembly_memory_server < cfg.fragmentation.max_total_reassembly_memory_per_peer) {
            return Result::fail(Errc::InvalidArg, "server reassembly memory budget must cover one peer budget");
        }
        return Result::success();
    }

} // namespace scn
