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
        U64 reliable_acks_sent{ 0 };
        U64 reliable_acks_received{ 0 };
        U64 reliable_retransmits{ 0 };
        U64 truncated_datagrams{ 0 };
        U64 socket_errors{ 0 };
        U64 queue_full_events{ 0 };
        U64 would_block_events{ 0 };
        U64 bad_packets{ 0 };

        void reset() {
            *this = {};
        }
    };

}
