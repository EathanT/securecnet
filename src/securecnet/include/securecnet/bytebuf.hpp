#pragma once
#include <cstddef>
#include <cstdint>
#include "securecnet/result.hpp"

namespace scn {

    // Network order (big-endian) helpers.

    struct ByteWriter {
        U8* dst{};
        ST cap{};
        ST off{0};

        ST remaining() const {
            return (off <= cap) ? (cap - off) : 0;
        }

        Result write_u8(U8 v);
        Result write_u16(U16 v);
        Result write_u32(U32 v);
        Result write_u64(U64 v);
        Result write_bytes(const void* p, ST n);
    };

    struct ByteReader {
        const U8* src{};
        ST len{};
        ST off{0};

        ST remaining() const {
            return (off <= len) ? (len - off) : 0;
        }

        Result read_u8(U8& v);
        Result read_u16(U16& v);
        Result read_u32(U32& v);
        Result read_u64(U64& v);
        Result read_bytes(void* p, ST n);

        const U8* peek_ptr(ST n) const;
        Result skip(ST n);
    };

<<<<<<< HEAD
}
=======
} // namespace scn
>>>>>>> origin/main
