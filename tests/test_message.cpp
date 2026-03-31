#include "securecnet/message.hpp"

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

int test_message() {

    U8 payload[128]{};
    ByteWriter w{ payload, sizeof(payload) };

    const char a[] = { 1,2,3 };
    const char b[] = { 'o','k' };

    if (!write_message(w, Channel::Unreliable, 10, a, 3).ok()) return 1;
    if (!write_message(w, Channel::Reliable, 20, b, 2).ok()) return 1;

    ByteReader r{ payload, w.off };

    MsgView m1{}, m2{};
    auto rc = read_message(r, m1);
    if (!rc.ok()) return 1;
    rc = read_message(r, m2);
    if (!rc.ok()) return 1;

    int fails = 0;
    fails += expect((U8)m1.channel == (U8)Channel::Unreliable, "m1 channel");
    fails += expect(m1.type == 10, "m1 type");
    fails += expect(m1.len == 3, "m1 len");
    fails += expect(std::memcmp(m1.data, a, 3) == 0, "m1 data");

    fails += expect((U8)m2.channel == (U8)Channel::Reliable, "m2 channel");
    fails += expect(m2.type == 20, "m2 type");
    fails += expect(m2.len == 2, "m2 len");
    fails += expect(std::memcmp(m2.data, b, 2) == 0, "m2 data");

    MsgView m3{};
    rc = read_message(r, m3);
    fails += expect(rc.code == Errc::EndOfStream, "expected EndOfStream at end");

    return fails;
}
