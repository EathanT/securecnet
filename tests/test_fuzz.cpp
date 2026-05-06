#include "securecnet/fragmentation.hpp"
#include "securecnet/message.hpp"
#include "securecnet/packet.hpp"
#include "securecnet/protocol.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_fuzz() {
    int fails = 0;

    std::mt19937_64 rng(0x53434E32ULL);
    std::uniform_int_distribution<int> len_dist(0, static_cast<int>(NetConfig::MaxPacketBytes + 32));
    std::uniform_int_distribution<int> byte_dist(0, 255);

    for (int i = 0; i < 2000; ++i) {
        const int len = len_dist(rng);
        std::vector<U8> bytes(static_cast<ST>(len));
        for (int j = 0; j < len; ++j) {
            bytes[static_cast<ST>(j)] = static_cast<U8>(byte_dist(rng));
        }

        PacketView packet{};
        auto rc = parse_packet(bytes.data(), bytes.size(), packet);
        if (rc.ok() && packet.h.payload_len > NetConfig::MaxPayloadBytes) {
            ++fails;
            std::printf("  fuzz: parse_packet accepted oversized payload\n");
            break;
        }

        ByteReader mr{ bytes.data(), bytes.size() };
        MsgView msg{};
        (void)read_message(mr, msg);

        ByteReader ch_r{ bytes.data(), bytes.size() };
        ClientHello ch{};
        (void)read_client_hello(ch_r, ch);

        ByteReader retry_r{ bytes.data(), bytes.size() };
        RetryToken retry{};
        (void)read_retry(retry_r, retry);

        ByteReader sh_r{ bytes.data(), bytes.size() };
        ServerHello sh{};
        (void)read_server_hello(sh_r, sh);

        ByteReader rt_r{ bytes.data(), bytes.size() };
        ResumptionToken resume{};
        (void)read_resumption_token(rt_r, resume);

        ByteReader frag_r{ bytes.data(), bytes.size() };
        FragmentView fragment{};
        (void)read_fragment_payload(frag_r, fragment);
    }

    fails += expect(true, "fuzz completed");
    return fails;
}
