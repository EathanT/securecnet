#include "bench_common.hpp"
#include "securecnet/fragmentation.hpp"

#include <array>
#include <vector>

using namespace scn;

static Result encode_fragment(std::span<const U8> payload, U64 message_id, U16 index, std::vector<U8>& out) {
    const U16 count = fragment_count_for_length(static_cast<U16>(payload.size()));
    const U16 len = fragment_size_for_index(static_cast<U16>(payload.size()), index);
    const ST offset = static_cast<ST>(index) * NetConfig::MaxFragmentDataBytes;
    out.assign(NetConfig::MaxEncryptedPlaintextBytes, 0);
    ByteWriter writer{ out.data(), out.size() };
    auto rc = write_fragment_payload(writer,
                                     message_id,
                                     1,
                                     Channel::ReliableOrdered,
                                     3,
                                     index,
                                     count,
                                     static_cast<U16>(payload.size()),
                                     payload.data() + offset,
                                     len);
    if (!rc.ok()) {
        return rc;
    }
    out.resize(writer.off);
    return Result::success();
}

int main() {
    constexpr std::size_t kTransfers = 50000;
    const auto payload = std::vector<U8>(4096, 0x5A);

    const long long total_ns = scn_bench::measure_ns([&]() {
        for (std::size_t i = 0; i < kTransfers; ++i) {
            FragmentReassembler reassembler{};
            FragmentationConfig cfg{};
            reassembler.configure(cfg);

            const U16 count = fragment_count_for_length(static_cast<U16>(payload.size()));
            for (U16 index = 0; index < count; ++index) {
                std::vector<U8> encoded{};
                auto rc = encode_fragment(std::span<const U8>(payload.data(), payload.size()),
                                          static_cast<U64>(i + 1),
                                          index,
                                          encoded);
                if (!rc.ok()) {
                    std::printf("encode_fragment failed: err=%u\n", static_cast<unsigned>(rc.code));
                    std::abort();
                }

                ByteReader reader{ encoded.data(), encoded.size() };
                FragmentView fragment{};
                rc = read_fragment_payload(reader, fragment);
                if (!rc.ok()) {
                    std::printf("read_fragment_payload failed: err=%u\n", static_cast<unsigned>(rc.code));
                    std::abort();
                }
                bool duplicate = false;
                bool completed = false;
                rc = reassembler.accept(static_cast<U64>(i + 1), fragment,
                                        [&](const FragmentedMessage&) {
                                            return Result::success();
                                        },
                                        duplicate,
                                        completed);
                if (!rc.ok()) {
                    std::printf("reassembler.accept failed: err=%u\n", static_cast<unsigned>(rc.code));
                    std::abort();
                }
            }
        }
    });

    scn_bench::print_rate("fragmented transfer", total_ns, kTransfers);
    return 0;
}
