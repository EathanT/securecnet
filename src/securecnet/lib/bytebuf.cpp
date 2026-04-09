#include "securecnet/bytebuf.hpp"
#include <cstring>

namespace scn {

    static Result need(ByteWriter& w, ST n) {
        return (w.remaining() >= n)
            ? Result::success()
            : Result::fail(Errc::Truncated, "ByteWriter overflow");
    }

    static Result need(ByteReader& r, ST n) {
        return (r.remaining() >= n)
            ? Result::success()
            : Result::fail(Errc::Truncated, "ByteReader underrun");
    }

    Result ByteWriter::write_u8(U8 v) {
        auto rc = need(*this, 1);
        if (!rc.ok()) return rc;
        
        dst[off++] = v;
        
        return Result::success();
    }

    Result ByteWriter::write_u16(U16 v) {
        auto rc = need(*this, 2);
        if (!rc.ok()) return rc;
        
        dst[off++] = static_cast<U8>((v >> 8) & 0xFFu);
        dst[off++] = static_cast<U8>(v & 0xFFu);
        
        return Result::success();
    }

    Result ByteWriter::write_u32(U32 v) {
        auto rc = need(*this, 4);
        if (!rc.ok()) return rc; 

        dst[off++] = static_cast<U8>((v >> 24) & 0xFFu);
        dst[off++] = static_cast<U8>((v >> 16) & 0xFFu);
        dst[off++] = static_cast<U8>((v >> 8) & 0xFFu);
        dst[off++] = static_cast<U8>(v & 0xFFu);
        
        return Result::success();
    }

    Result ByteWriter::write_u64(U64 v) {
        auto rc = need(*this, 8);
        if (!rc.ok()) return rc;
        
        for (int i = 7; i >= 0; --i)
            dst[off++] = static_cast<U8>((v >> (i * 8)) & 0xFFu);
        
        return Result::success();
    }

    Result ByteWriter::write_bytes(const void* p, ST n) {
        if (n > 0 && !p) {
            return Result::fail(Errc::InvalidArg, "ByteWriter source is null");
        }

        auto rc = need(*this, n);
        if (!rc.ok()) return rc;
       
        if (n > 0) {
            std::memcpy(dst + off, p, n);
            off += n;
        }
        
        return Result::success();
    }

    Result ByteReader::read_u8(U8& v) {
        auto rc = need(*this, 1);
        if (!rc.ok()) return rc;
        
        v = src[off++];
       
        return Result::success();
    }

    Result ByteReader::read_u16(U16& v) {
        auto rc = need(*this, 2);
        if (!rc.ok()) return rc;
        v = (static_cast<U16>(src[off]) << 8) |
            (static_cast<U16>(src[off + 1]));
        off += 2;
        
        return Result::success();
    }

    Result ByteReader::read_u32(U32& v) {
        auto rc = need(*this, 4);
        if (!rc.ok()) return rc;
        
        v = (static_cast<U32>(src[off]) << 24) |
            (static_cast<U32>(src[off + 1]) << 16) |
            (static_cast<U32>(src[off + 2]) << 8) |
            (static_cast<U32>(src[off + 3]));
        off += 4;
        
        return Result::success();
    }

    Result ByteReader::read_u64(U64& v) {
        auto rc = need(*this, 8);
        if (!rc.ok()) 
            return rc;

        v = 0;
        for (int i = 0; i < 8; ++i)
            v = (v << 8) | src[off + i];
        off += 8;
        
        return Result::success();
    }

    Result ByteReader::read_bytes(void* p, ST n) {
        if (n > 0 && !p) {
            return Result::fail(Errc::InvalidArg, "ByteReader destination is null");
        }

        auto rc = need(*this, n);
        if (!rc.ok()) return rc;
       
        if (n > 0) {
            std::memcpy(p, src + off, n);
            off += n;
        }
        
        return Result::success();
    }

    const uint8_t* ByteReader::peek_ptr(ST n) const {
        if (remaining() < n)
            return nullptr;
        
        return src + off;
    }

    Result ByteReader::skip(ST n) {
        auto rc = need(*this, n);
        if (!rc.ok()) return rc;
        off += n;
        
        return Result::success();
    }

} 