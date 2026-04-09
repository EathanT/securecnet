#pragma once
#include <cstdint>
#include <cstddef>
#include <span>
#include <string_view>
#include "securecnet/result.hpp"
#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"

namespace scn {

    enum class Channel : U8 {
        Unreliable = 0,
        Reliable = 1,
        Control = 2, // internal transport frames
    };

    struct MsgView {
        Channel channel{};
        U8 type{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };

        std::span<const U8> bytes() const {
            if (!data || len == 0) {
                return {};
            }

            return std::span<const U8>(data, len);
        }

        std::string_view text() const {
            if (!data || len == 0) {
                return {};
            }

            return std::string_view(reinterpret_cast<const char*>(data), len);
        }
    };

    // Writes: [ch][type][len][bytes]
    inline Result write_message(ByteWriter& w, Channel ch, U8 type,
        const void* data, U16 len)
    {
        if (len > static_cast<U16>(NetConfig::MaxMessageBytes)) {
			return Result::fail(Errc::InvalidArg, "message payload too large");
        }
        if (len > 0 && !data) {
			return Result::fail(Errc::InvalidArg, "message data is null");
        }

        Result r;
        r = w.write_u8(static_cast<U8>(ch));
        if (!r.ok()) return r;

        r = w.write_u8(type);
        if (!r.ok()) return r;

        r = w.write_u16(len);
        if (!r.ok()) return r;

        if (len > 0) {
            r = w.write_bytes(data, len);
            if (!r.ok()) return r;
        }

        return Result::success();
    }

    /*
     * Reads next message frame. Sets out and returns Ok.
     * If no more data, returns Errc::EndOfStream.
     * If bad, returns Errc::BadPacket.
     */
    inline Result read_message(ByteReader& r, MsgView& out)
    {
        if (r.remaining() == 0)
            return Result::fail(Errc::EndOfStream, "no more messages");

        if (r.remaining() < NetConfig::MessageHeaderBytes)
            return Result::fail(Errc::BadPacket, "truncated message header");

        U8 ch = 0, type = 0;
        U16 len = 0;

        Result rc;
        rc = r.read_u8(ch);
        if (!rc.ok()) return rc;

        rc = r.read_u8(type);
        if (!rc.ok()) return rc;

        rc = r.read_u16(len);
        if (!rc.ok()) return rc;


        if (ch > static_cast<U8>(Channel::Control)) {
            return Result::fail(Errc::BadPacket, "invalid message channel");
        }

        if (len > r.remaining())
            return Result::fail(Errc::BadPacket, "message len exceeds payload");

        out.channel = static_cast<Channel>(ch);
        out.type = type;
        out.len = len;
        out.data = (len == 0) ? nullptr : r.peek_ptr(len);

        // Advance past the message bytes
        rc = r.skip(len);
        return rc;
    }

}
