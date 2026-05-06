#include "bench_common.hpp"
#include "securecnet/packet.hpp"

#include <array>

using namespace scn;

int main() {
    constexpr std::size_t kIterations = 250000;
    std::array<U8, 256> payload{};
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<U8>((i * 3u) & 0xFFu);
    }

    PacketHeader header{};
    header.kind = static_cast<U8>(PacketKind::Message);
    header.flags = 0;
    header.conn_id = 0x12345678ULL;
    header.seq = 0xABCDEFULL;
    header.payload_len = static_cast<U32>(payload.size());

    std::array<U8, NetConfig::MaxPacketBytes> encoded{};
    ST out_len = 0;

    const long long total_ns = scn_bench::measure_ns([&]() {
        for (std::size_t i = 0; i < kIterations; ++i) {
            header.seq = static_cast<U64>(i + 1);
            auto rc = pack_packet(header, payload.data(), payload.size(), encoded.data(), encoded.size(), out_len);
            if (!rc.ok()) {
                std::printf("pack_packet failed: err=%u\n", static_cast<unsigned>(rc.code));
                std::abort();
            }
            PacketView view{};
            rc = parse_packet(encoded.data(), out_len, view);
            if (!rc.ok()) {
                std::printf("parse_packet failed: err=%u\n", static_cast<unsigned>(rc.code));
                std::abort();
            }
        }
    });

    scn_bench::print_rate("packet encode+decode", total_ns, kIterations);
    return 0;
}
