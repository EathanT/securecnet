#include "securecnet/packet.hpp"

namespace scn {

    namespace {
        constexpr ST kHeaderBytes = packet_header_bytes();

        constexpr ST max_payload_bytes() {
            return (NetConfig::MaxPacketBytes > kHeaderBytes)
                ? (NetConfig::MaxPacketBytes - kHeaderBytes)
                : 0;
        }

        Result validate_packet_header(const PacketHeader& h) {
            if (h.magic != NetConfig::Magic) {
                return Result::fail(Errc::BadPacket, "bad magic");
            }
            if (h.version != NetConfig::ProtocolVersion) {
                return Result::fail(Errc::UnsupportedVersion, "unsupported version");
            }
            if (!packet_kind_valid(h.kind)) {
                return Result::fail(Errc::BadPacket, "invalid packet kind");
            }
            if ((h.flags & ~PacketKnownFlags) != 0) {
                return Result::fail(Errc::BadPacket, "invalid packet flags");
            }
            if (h.payload_len > max_payload_bytes()) {
                return Result::fail(Errc::BadPacket, "payload_len exceeds max");
            }
            return Result::success();
        }
    }

    Result write_packet_header(ByteWriter& w, const PacketHeader& h) {
        Result rc;
        rc = w.write_u32(h.magic);
        if (!rc.ok()) return rc;
        rc = w.write_u16(h.version);
        if (!rc.ok()) return rc;
        rc = w.write_u8(h.kind);
        if (!rc.ok()) return rc;
        rc = w.write_u8(h.flags);
        if (!rc.ok()) return rc;
        rc = w.write_u64(h.conn_id);
        if (!rc.ok()) return rc;
        rc = w.write_u64(h.seq);
        if (!rc.ok()) return rc;
        rc = w.write_u32(h.payload_len);
        if (!rc.ok()) return rc;
        return Result::success();
    }

    Result read_packet_header(ByteReader& r, PacketHeader& h) {
        Result rc;
        rc = r.read_u32(h.magic);
        if (!rc.ok()) return rc;
        rc = r.read_u16(h.version);
        if (!rc.ok()) return rc;
        rc = r.read_u8(h.kind);
        if (!rc.ok()) return rc;
        rc = r.read_u8(h.flags);
        if (!rc.ok()) return rc;
        rc = r.read_u64(h.conn_id);
        if (!rc.ok()) return rc;
        rc = r.read_u64(h.seq);
        if (!rc.ok()) return rc;
        rc = r.read_u32(h.payload_len);
        if (!rc.ok()) return rc;
        return Result::success();
    }

    Result pack_packet(const PacketHeader& h,
                       const U8* payload, ST payload_len,
                       U8* out, ST out_cap, ST& out_len) {
        out_len = 0;

        if (!out) {
            return Result::fail(Errc::InvalidArg, "out is null");
        }
        if (payload_len > 0 && !payload) {
            return Result::fail(Errc::InvalidArg, "payload is null");
        }
        if (payload_len > max_payload_bytes()) {
            return Result::fail(Errc::InvalidArg, "payload too large");
        }
        if (h.payload_len != static_cast<U32>(payload_len)) {
            return Result::fail(Errc::InvalidArg, "header payload_len mismatch");
        }

        auto rc = validate_packet_header(h);
        if (!rc.ok() && rc.code != Errc::UnsupportedVersion) {
            return rc;
        }

        const ST total = kHeaderBytes + payload_len;
        if (out_cap < total) {
            return Result::fail(Errc::Truncated, "out buffer too small");
        }

        ByteWriter w{ out, out_cap };
        rc = write_packet_header(w, h);
        if (!rc.ok()) {
            return rc;
        }
        if (payload_len > 0) {
            rc = w.write_bytes(payload, payload_len);
            if (!rc.ok()) {
                return rc;
            }
        }

        out_len = w.off;
        return Result::success();
    }

    Result parse_packet(const U8* in, ST in_len, PacketView& out) {
        out = {};

        if (!in) {
            return Result::fail(Errc::InvalidArg, "in is null");
        }
        if (in_len < kHeaderBytes) {
            return Result::fail(Errc::Truncated, "packet header truncated");
        }

        ByteReader r{ in, in_len };
        auto rc = read_packet_header(r, out.h);
        if (!rc.ok()) {
            return rc;
        }
        rc = validate_packet_header(out.h);
        if (!rc.ok()) {
            return rc;
        }

        if (r.remaining() < static_cast<ST>(out.h.payload_len)) {
            return Result::fail(Errc::Truncated, "payload truncated");
        }
        if (r.remaining() != static_cast<ST>(out.h.payload_len)) {
            return Result::fail(Errc::BadPacket, "extra bytes after payload");
        }

        out.payload = (out.h.payload_len == 0) ? nullptr : (in + r.off);
        return Result::success();
    }

} // namespace scn
