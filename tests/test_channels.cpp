#include "securecnet/reliability.hpp"

#include <cstdio>
#include <vector>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_channels() {
    int fails = 0;

    {
        OrderedReceiveWindow ordered{ 4 };
        std::vector<U64> release_order{};

        bool buffered = false;
        bool stale = false;
        auto rc = ordered.accept(2, 1, nullptr, 0,
                                 [&](U8, const U8*, U16) {
                                     release_order.push_back(2);
                                     return Result::success();
                                 },
                                 buffered, stale);
        fails += expect(rc.ok(), "ordered window should accept first out-of-order packet");
        fails += expect(buffered, "ordered window should buffer out-of-order packet");
        fails += expect(!stale, "ordered window should not mark buffered packet stale");
        fails += expect(release_order.empty(), "ordered window should not deliver packet 2 before packet 1");

        rc = ordered.accept(1, 2, nullptr, 0,
                            [&](U8, const U8*, U16) {
                                release_order.push_back(static_cast<U64>(release_order.size() + 1));
                                return Result::success();
                            },
                            buffered, stale);
        fails += expect(rc.ok(), "ordered window should accept packet 1");
        fails += expect(!buffered, "ordered window should not buffer packet 1");
        fails += expect(release_order.size() == 2, "ordered window should release packet 1 and buffered packet 2");
        fails += expect(release_order[0] == 1 && release_order[1] == 2,
                        "ordered window should release packets in-order");

        rc = ordered.accept(2, 3, nullptr, 0,
                            [&](U8, const U8*, U16) {
                                return Result::success();
                            },
                            buffered, stale);
        fails += expect(rc.ok(), "ordered window should tolerate duplicate stale packet");
        fails += expect(stale, "ordered window should mark duplicate stale packet");
    }

    {
        OrderedReceiveWindow ordered{ 1 };
        bool buffered = false;
        bool stale = false;
        auto rc = ordered.accept(3, 1, nullptr, 0,
                                 [&](U8, const U8*, U16) {
                                     return Result::success();
                                 },
                                 buffered, stale);
        fails += expect(rc.ok(), "ordered window should buffer first out-of-order packet");
        rc = ordered.accept(4, 1, nullptr, 0,
                            [&](U8, const U8*, U16) {
                                return Result::success();
                            },
                            buffered, stale);
        fails += expect(!rc.ok() && rc.code == Errc::QueueFull,
                        "ordered window should reject packets when buffer is full");
    }

    {
        SequencedReceiveWindow sequenced{};
        fails += expect(!sequenced.accept(0), "sequenced window should reject zero sequence");
        fails += expect(sequenced.accept(5), "sequenced window should accept first valid sequence");
        fails += expect(!sequenced.accept(4), "sequenced window should reject older sequence");
        fails += expect(!sequenced.accept(5), "sequenced window should reject duplicate sequence");
        fails += expect(sequenced.accept(6), "sequenced window should accept newer sequence");
        fails += expect(sequenced.latest() == 6, "sequenced window latest sequence mismatch");
    }

    return fails;
}
