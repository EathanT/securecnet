#include "securecnet/bytebuf.hpp"
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

<<<<<<< HEAD

=======
>>>>>>> origin/main
int test_bytebuf() {

    U8 buf[64]{};
    ByteWriter w{ buf, sizeof(buf) };

    if (!w.write_u8(0xAB).ok()) return 1;
    if (!w.write_u16(0x1234).ok()) return 1;
    if (!w.write_u32(0xDEADBEEF).ok()) return 1;
    if (!w.write_u64(0x1122334455667788ULL).ok()) return 1;

    const char* s = "hi";
    if (!w.write_bytes(s, 2).ok()) return 1;

    ByteReader r{ buf, w.off };

    U8  a = 0; U16 b = 0; U32 c = 0; U64 d = 0;
    char t[3] = { 0,0,0 };

    if (!r.read_u8(a).ok()) return 1;
    if (!r.read_u16(b).ok()) return 1;
    if (!r.read_u32(c).ok()) return 1;
    if (!r.read_u64(d).ok()) return 1;
    if (!r.read_bytes(t, 2).ok()) return 1;

    int fails = 0;
    fails += expect(a == 0xAB, "u8 mismatch");
    fails += expect(b == 0x1234, "u16 mismatch");
    fails += expect(c == 0xDEADBEEF, "u32 mismatch");
    fails += expect(d == 0x1122334455667788ULL, "u64 mismatch");
    fails += expect(std::memcmp(t, "hi", 2) == 0, "bytes mismatch");
    fails += expect(r.remaining() == 0, "reader should be at end");

    return fails;
}