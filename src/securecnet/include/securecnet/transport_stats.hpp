#pragma once

#include "securecnet/util/util.h"

namespace scn {

    struct TransportStats {
        U64 packets_sent{ 0 };
        U64 packets_received{ 0 };
        U64 message_frames_sent{ 0 };
        U64 message_frames_received{ 0 };
        U64 bytes_sent{ 0 };
        U64 bytes_received{ 0 };

        U64 reliable_message_enqueued{ 0 };
        U64 reliable_messages_delivered{ 0 };
        U64 reliable_messages_dropped{ 0 };
        U64 reliable_acks_sent{ 0 };
        U64 reliable_acks_received{ 0 };
        U64 reliable_retransmits{ 0 };
        U64 reliable_expired{ 0 };
        U64 reliable_loss_events{ 0 };
        U64 ordered_messages_received{ 0 };
        U64 ordered_messages_released{ 0 };
        U64 ordered_messages_buffered{ 0 };
        U64 ordered_messages_dropped{ 0 };
        U64 sequenced_messages_received{ 0 };
        U64 sequenced_messages_dropped{ 0 };

        U64 fragmented_messages_sent{ 0 };
        U64 fragmented_messages_received{ 0 };
        U64 fragments_sent{ 0 };
        U64 fragments_received{ 0 };
        U64 fragment_duplicates{ 0 };
        U64 fragment_invalid_sets{ 0 };
        U64 reassemblies_completed{ 0 };
        U64 reassemblies_expired{ 0 };
        U64 reassembly_drops{ 0 };
        U64 reassembly_memory_rejections{ 0 };

        U64 handshake_attempts{ 0 };
        U64 handshake_successes{ 0 };
        U64 handshake_failures{ 0 };
        U64 handshake_retries_sent{ 0 };
        U64 handshake_retries_received{ 0 };
        U64 sessions_established{ 0 };
        U64 session_resumptions_attempted{ 0 };
        U64 session_resumptions_accepted{ 0 };
        U64 session_resumptions_rejected{ 0 };
        U64 keepalives_sent{ 0 };
        U64 keepalives_received{ 0 };
        U64 closes_sent{ 0 };
        U64 closes_received{ 0 };
        U64 idle_timeouts{ 0 };
        U64 establish_timeouts{ 0 };
        U64 peers_evicted{ 0 };
        U64 state_transitions{ 0 };

        U64 auth_failures{ 0 };
        U64 decrypt_failures{ 0 };
        U64 replays_dropped{ 0 };
        U64 unsupported_version_packets{ 0 };
        U64 bad_packets{ 0 };
        U64 protocol_errors{ 0 };
        U64 truncated_datagrams{ 0 };
        U64 socket_errors{ 0 };
        U64 queue_full_events{ 0 };
        U64 would_block_events{ 0 };
        U64 dropped_packets{ 0 };
        U64 rate_limited_packets{ 0 };
        U64 invalid_packet_penalties{ 0 };
        U64 amplification_drops{ 0 };
        U64 backpressure_events{ 0 };

        U64 send_budget_refills{ 0 };
        U64 send_budget_throttles{ 0 };

        U64 rtt_latest_ms{ 0 };
        U64 rtt_smoothed_ms{ 0 };
        U64 rtt_variance_ms{ 0 };
        U64 current_retransmit_timeout_ms{ 0 };
        U64 current_peer_count{ 0 };
        U64 current_pending_packets{ 0 };
        U64 current_reliable_pending{ 0 };
        U64 current_reliable_inflight{ 0 };
        U64 current_reassembly_count{ 0 };
        U64 current_reassembly_memory_bytes{ 0 };
        U64 current_send_budget_bytes{ 0 };
        U64 estimated_loss_per_mille{ 0 };

        U64 congestion_current_rate_bytes_per_second{ 0 };
        U64 congestion_current_window_bytes{ 0 };
        U64 congestion_ack_events{ 0 };
        U64 congestion_loss_events{ 0 };
        U64 congestion_backpressure_events{ 0 };

        void reset() {
            *this = {};
        }
    };

} // namespace scn
