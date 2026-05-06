#include "securecnet/packet.hpp"

#include <cstdio>
#include <cstring>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

static constexpr ST kHeaderBytes = NetConfig::PacketHeaderBytes;

int test_packet() {
    int fails = 0;

    {
        PacketHeader h{};
        h.kind = static_cast<U8>(PacketKind::Message);
        h.flags = PacketFlagEncrypted;
        h.conn_id = 0x1122334455667788ULL;
        h.seq = 12345;
        h.payload_len = 16;

        U8 payload[16]{};
        for (int i = 0; i < 16; ++i) payload[i] = static_cast<U8>(i);

        U8 buf[NetConfig::MaxPacketBytes]{};
        ST out_len = 0;
        auto rc = pack_packet(h, payload, sizeof(payload), buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "roundtrip: pack failed");
        fails += expect(out_len == kHeaderBytes + sizeof(payload), "roundtrip: size mismatch");

        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.ok(), "roundtrip: parse failed");
        fails += expect(pv.h.magic == NetConfig::Magic, "roundtrip: magic mismatch");
        fails += expect(pv.h.version == NetConfig::ProtocolVersion, "roundtrip: version mismatch");
        fails += expect(pv.h.kind == h.kind, "roundtrip: kind mismatch");
        fails += expect(pv.h.flags == h.flags, "roundtrip: flags mismatch");
        fails += expect(pv.h.conn_id == h.conn_id, "roundtrip: conn_id mismatch");
        fails += expect(pv.h.seq == h.seq, "roundtrip: seq mismatch");
        fails += expect(pv.h.payload_len == sizeof(payload), "roundtrip: payload_len mismatch");
        fails += expect(pv.payload != nullptr, "roundtrip: payload pointer null");
        fails += expect(std::memcmp(pv.payload, payload, sizeof(payload)) == 0, "roundtrip: payload bytes mismatch");
    }

    {
        PacketHeader h{};
        h.kind = static_cast<U8>(PacketKind::Raw);
        h.payload_len = 1;
        U8 payload[1]{ 0xAA };
        U8 buf[64]{};
        ST out_len = 0;
        auto rc = pack_packet(h, payload, 1, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "bad magic: pack failed unexpectedly");
        buf[0] ^= 0xFF;
        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::BadPacket, "bad magic: expected BadPacket");
    }

    {
        PacketHeader h{};
        h.kind = static_cast<U8>(PacketKind::Raw);
        h.payload_len = 1;
        U8 payload[1]{ 0xBB };
        U8 buf[64]{};
        ST out_len = 0;
        auto rc = pack_packet(h, payload, 1, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "bad version: pack failed unexpectedly");
        buf[4] = 0x00;
        buf[5] = 0x01;
        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::UnsupportedVersion, "bad version: expected UnsupportedVersion");
    }

    {
        PacketHeader h{};
        h.kind = static_cast<U8>(PacketKind::Raw);
        h.payload_len = 4;
        U8 payload[4]{ 1,2,3,4 };
        U8 buf[64]{};
        ST out_len = 0;
        auto rc = pack_packet(h, payload, 4, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "truncate: pack failed unexpectedly");
        buf[24] = 0x00; buf[25] = 0x00; buf[26] = 0x00; buf[27] = 0x64;
        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::Truncated, "truncate: expected Truncated for oversized payload_len");
    }

    {
        PacketHeader h{};
        h.kind = static_cast<U8>(PacketKind::Raw);
        h.payload_len = 4;
        U8 payload[4]{ 9,9,9,9 };
        U8 buf[64]{};
        ST out_len = 0;
        auto rc = pack_packet(h, payload, 4, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "extra bytes: pack failed unexpectedly");
        buf[24] = 0x00; buf[25] = 0x00; buf[26] = 0x00; buf[27] = 0x01;
        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::BadPacket, "extra bytes: expected BadPacket");
    }

    {
        PacketHeader h{};
        h.kind = 99;
        h.payload_len = 0;
        U8 buf[64]{};
        ST out_len = 0;
        auto rc = pack_packet(h, nullptr, 0, buf, sizeof(buf), out_len);
        fails += expect(!rc.ok() && rc.code == Errc::BadPacket, "invalid kind should be rejected on pack");
    }

    return fails;
}
