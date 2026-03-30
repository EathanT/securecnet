#include "securecnet/packet.hpp"
#include "securecnet/bytebuf.hpp"

namespace scn {

    static constexpr ST kHeaderBytes =
          4  // magic (u32)
        + 2  // version (u16)
        + 2  // flags (u16)
        + 8  // conn_id (u64)
        + 8  // seq (u64)
        + 4; // payload_len (u32)


	// MaxPacketBytes includes the header + payload, so the max payload is MaxPacketBytes - header
    static constexpr ST max_payload_bytes() {
        return (NetConfig::MaxPacketBytes > kHeaderBytes)
            ? (NetConfig::MaxPacketBytes - kHeaderBytes)
            : 0;
    }

    Result pack_packet(const PacketHeader& h,
        const U8* payload, ST payload_len,
        U8* out, ST out_cap, ST& out_len)
    {
        out_len = 0;

        // Pre-Checks, incase user is a littttle dumb
        if (!out)
            return Result::fail(Errc::InvalidArg, "out is null");
        
        if (payload_len > 0 && !payload)
            return Result::fail(Errc::InvalidArg, "payload is null");
        
        if (payload_len > max_payload_bytes())
            return Result::fail(Errc::InvalidArg, "payload too large");
       
        const ST total = kHeaderBytes + payload_len;
        if (out_cap < total)
            return Result::fail(Errc::Truncated, "out buffer too small");

        ByteWriter w{ out, out_cap };


		// Write Magic, Version, Flags, ConnID, Seq, PayloadLen
        Result r;
        r = w.write_u32(NetConfig::Magic);
        if (!r.ok()) return r;
        
        r = w.write_u16(NetConfig::ProtocolVersion);
        if (!r.ok()) return r;
        
        r = w.write_u16(h.flags);
        if (!r.ok()) return r;
        
        r = w.write_u64(h.conn_id);
        if (!r.ok()) return r;
        
        r = w.write_u64(h.seq);
        if (!r.ok()) return r;
        
        r = w.write_u32(static_cast<U32>(payload_len));
        if (!r.ok()) return r;

        if (payload_len > 0) {
            r = w.write_bytes(payload, payload_len);
            if (!r.ok()) return r;
        }

        out_len = w.off;
        return Result::success();
    }

    Result parse_packet(const U8* in, ST in_len, PacketView& out)
    {
        out = {};

        
        if (!in)
            return Result::fail(Errc::InvalidArg, "in is null");
        
        if (in_len < kHeaderBytes)
            return Result::fail(Errc::Truncated, "packet header truncated");

        ByteReader r{ in, in_len };

		// Read Magic, Version, Flags, ConnID, Seq, PayloadLen
        Result rc;
        rc = r.read_u32(out.h.magic);
        if (!rc.ok()) return rc;
        
        rc = r.read_u16(out.h.version);
        if (!rc.ok()) return rc;
        
        rc = r.read_u16(out.h.flags);
        if (!rc.ok()) return rc;
        
        rc = r.read_u64(out.h.conn_id);
        if (!rc.ok()) return rc;
        
        rc = r.read_u64(out.h.seq);
        if (!rc.ok()) return rc;
        
        rc = r.read_u32(out.h.payload_len);
        if (!rc.ok()) return rc;

        
        // Validate header fields
        if (out.h.magic != NetConfig::Magic)
            return Result::fail(Errc::BadPacket, "bad magic");

        if (out.h.version != NetConfig::ProtocolVersion)
            return Result::fail(Errc::BadPacket, "bad version");

        if (out.h.payload_len > max_payload_bytes())
            return Result::fail(Errc::BadPacket, "payload_len exceeds max");

        // Must have exactly payload_len bytes remaining
        if (r.remaining() < static_cast<ST>(out.h.payload_len))
            return Result::fail(Errc::Truncated, "payload truncated");

        if (r.remaining() != static_cast<ST>(out.h.payload_len))
            return Result::fail(Errc::BadPacket, "extra bytes after payload");

        out.payload = in + r.off;
        return Result::success();
    }

} 