#pragma once
#include <cstdint>
#include <cstddef>
#include "securecnet/result.hpp"
#include "securecnet/config.hpp"

namespace scn {

    // Header is a fixed-size
    struct PacketHeader {
        U32 magic{ NetConfig::Magic };
        U16 version{ NetConfig::ProtocolVersion };
        U16 flags{ 0 };

        U64 conn_id{ 0 };
        U64 seq{ 0 };        // packet sequence
        U32 payload_len{ 0 };
    };

    struct PacketView {
        PacketHeader h{};
        const U8* payload{};
    };

    // Pack header + payload into out buffer
    Result pack_packet(const PacketHeader& h,
        const U8* payload, ST payload_len,
        U8* out, ST out_cap, ST& out_len);

    // Parse header and return view into input buffer
    Result parse_packet(const U8* in, ST in_len, PacketView& out);

} // namespace scn