#pragma once
#include <cstddef>
#include <cstdint>
#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"
#include "securecnet/result.hpp"

namespace scn {

    enum class PacketKind : U8 {
        Raw = 0,
        Handshake = 1,
        Message = 2,
        Keepalive = 3,
        Close = 4,
    };

    static constexpr U8 PacketFlagEncrypted = 0x01;
    static constexpr U8 PacketKnownFlags = PacketFlagEncrypted;

    struct PacketHeader {
        U32 magic{ NetConfig::Magic };
        U16 version{ NetConfig::ProtocolVersion };
        U8 kind{ static_cast<U8>(PacketKind::Raw) };
        U8 flags{ 0 };
        U64 conn_id{ 0 };
        U64 seq{ 0 };
        U32 payload_len{ 0 };
    };

    struct PacketView {
        PacketHeader h{};
        const U8* payload{};
    };

    constexpr ST packet_header_bytes() {
        return NetConfig::PacketHeaderBytes;
    }

    constexpr bool packet_kind_valid(U8 kind) {
        return kind <= static_cast<U8>(PacketKind::Close);
    }

    constexpr bool packet_header_encrypted(const PacketHeader& h) {
        return (h.flags & PacketFlagEncrypted) != 0;
    }

    Result write_packet_header(ByteWriter& w, const PacketHeader& h);
    Result read_packet_header(ByteReader& r, PacketHeader& h);

    Result pack_packet(const PacketHeader& h,
                       const U8* payload, ST payload_len,
                       U8* out, ST out_cap, ST& out_len);

    Result parse_packet(const U8* in, ST in_len, PacketView& out);

} // namespace scn
