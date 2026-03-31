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

static constexpr ST kHeaderBytes = 28; // our header is always 28 bytes

int test_packet()
{

    int fails = 0;

    // roundtrip
    {
        PacketHeader h{};
        h.flags = 0x55AA;
        h.conn_id = 0x1122334455667788ULL;
        h.seq = 12345;

        const U8 size = 16;

        U8 payload[size]{};
        for (int i = 0; i < size; ++i) payload[i] = (U8)i;

        U8 buf[NetConfig::MaxPacketBytes]{};
        ST out_len = 0;

        auto rc = pack_packet(h, payload, size, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "roundtrip: pack failed");
        fails += expect(out_len == (ST)(kHeaderBytes + 16), "roundtrip: size mismatch");

        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.ok(), "roundtrip: parse failed");

        fails += expect(pv.h.magic == NetConfig::Magic, "roundtrip: magic mismatch");
        fails += expect(pv.h.version == NetConfig::ProtocolVersion, "roundtrip: version mismatch");
        fails += expect(pv.h.flags == h.flags, "roundtrip: flags mismatch");
        fails += expect(pv.h.conn_id == h.conn_id, "roundtrip: conn_id mismatch");
        fails += expect(pv.h.seq == h.seq, "roundtrip: seq mismatch");
        fails += expect(pv.h.payload_len == 16, "roundtrip: payload_len mismatch");
        fails += expect(std::memcmp(pv.payload, payload, 16) == 0, "roundtrip: payload bytes mismatch");
    }

    // bad magic
    {
        PacketHeader h{};
        U8 payload[1]{ 0xAA };
        U8 buf[64]{};
        ST out_len = 0;

        auto rc = pack_packet(h, payload, 1, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "bad magic: pack failed unexpectedly");

        buf[0] ^= 0xFF; // corrupt magic
        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::BadPacket, "bad magic: expected BadPacket");
    }

    // bad version
    {
        PacketHeader h{};
        U8 payload[1]{ 0xBB };
        U8 buf[64]{};
        ST out_len = 0;

        auto rc = pack_packet(h, payload, 1, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "bad version: pack failed unexpectedly");

        // version is bytes [4 and 5] big-endian
        buf[4] = 0x00;
        buf[5] = 0x02;

        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::BadPacket, "bad version: expected BadPacket");
    }

    // payload_len is more than actual
    {
        PacketHeader h{};
        U8 payload[4]{ 1,2,3,4 };
        U8 buf[64]{};
        ST out_len = 0;

        auto rc = pack_packet(h, payload, 4, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "truncate: pack failed unexpectedly");

        // payload_len field is bytes [24..27] (big-endian u32). Set to 100.
        buf[24] = 0x00; buf[25] = 0x00; buf[26] = 0x00; buf[27] = 0x64;

        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::Truncated, "truncate: expected Truncated");
    }

    // Case 5: extra bytes after payload
    {
        PacketHeader h{};
        U8 payload[4]{ 9,9,9,9 };
        U8 buf[64]{};
        ST out_len = 0;

        auto rc = pack_packet(h, payload, 4, buf, sizeof(buf), out_len);
        fails += expect(rc.ok(), "extra bytes: pack failed unexpectedly");

        // Make payload_len smaller than actual
        buf[24] = 0x00; buf[25] = 0x00; buf[26] = 0x00; buf[27] = 0x01;

        PacketView pv{};
        rc = parse_packet(buf, out_len, pv);
        fails += expect(rc.code == Errc::BadPacket, "extra bytes: expected BadPacket");
    }

    return fails;
}
