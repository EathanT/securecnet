#pragma once
#include <cstdint>
#include <cstddef>
<<<<<<< HEAD
#include <span>
#include <string_view>
=======
>>>>>>> origin/main
#include "securecnet/result.hpp"
#include "securecnet/bytebuf.hpp"

namespace scn {

    enum class Channel : U8{ Unreliable = 0, Reliable = 1 };

    struct MsgView {
        Channel channel{};
        U8 type{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };
<<<<<<< HEAD

        std::span<const U8> bytes() const {
            return std::span<const U8>(data, len);
        }
   
        std::string_view text() const {
            return std::string_view(reinterpret_cast<const char*>(data), len);
        }
=======
>>>>>>> origin/main
    };

    // Writes: [ch][type][len][bytes]
    inline Result write_message(ByteWriter& w, Channel ch, U8 type,
        const void* data, U16 len)
    {
        // sanity check 
        if (len > 1200)
            return Result::fail(Errc::InvalidArg, "message too large");

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
     * Reads next message frame.Sets out and returns Ok.
     * If no more data, returns Errc::EndOfStream.
     * If Bad, returns Errc::BadPacket. 
    */
    inline Result read_message(ByteReader& r, MsgView& out)
    {
        if (r.remaining() == 0)
            return Result::fail(Errc::EndOfStream, "no more messages");
        
        if (r.remaining() < 4)
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