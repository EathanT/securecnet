#include "bench_common.hpp"
#include "securecnet/fragmentation.hpp"
#include "securecnet/packet.hpp"
#include "securecnet/reliability.hpp"

#include <array>
#include <atomic>
#include <cstdlib>
#include <new>
#include <vector>

static std::atomic<std::size_t> g_alloc_count{ 0 };
static std::atomic<std::size_t> g_alloc_bytes{ 0 };

void* operator new(std::size_t size) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    g_alloc_bytes.fetch_add(size, std::memory_order_relaxed);
    if (void* ptr = std::malloc(size)) {
        return ptr;
    }
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    g_alloc_bytes.fetch_add(size, std::memory_order_relaxed);
    if (void* ptr = std::malloc(size)) {
        return ptr;
    }
    throw std::bad_alloc();
}

void operator delete(void* ptr) noexcept {
    std::free(ptr);
}

void operator delete[](void* ptr) noexcept {
    std::free(ptr);
}

void operator delete(void* ptr, std::size_t) noexcept {
    std::free(ptr);
}

void operator delete[](void* ptr, std::size_t) noexcept {
    std::free(ptr);
}

using namespace scn;

static void reset_alloc_counters() {
    g_alloc_count.store(0, std::memory_order_relaxed);
    g_alloc_bytes.store(0, std::memory_order_relaxed);
}

static void print_alloc_profile(const char* label, std::size_t ops) {
    const std::size_t count = g_alloc_count.load(std::memory_order_relaxed);
    const std::size_t bytes = g_alloc_bytes.load(std::memory_order_relaxed);
    const double allocs_per_op = (ops == 0) ? 0.0 : static_cast<double>(count) / static_cast<double>(ops);
    const double bytes_per_op = (ops == 0) ? 0.0 : static_cast<double>(bytes) / static_cast<double>(ops);
    std::printf("%-28s allocs=%zu bytes=%zu allocs/op=%.4f bytes/op=%.2f\n",
                label, count, bytes, allocs_per_op, bytes_per_op);
}

int main() {
    constexpr std::size_t kIterations = 10000;

    {
        std::array<U8, 96> payload{};
        PacketHeader header{};
        header.kind = static_cast<U8>(PacketKind::Message);
        header.payload_len = static_cast<U32>(payload.size());
        std::array<U8, NetConfig::MaxPacketBytes> encoded{};
        ST out_len = 0;

        reset_alloc_counters();
        for (std::size_t i = 0; i < kIterations; ++i) {
            header.seq = static_cast<U64>(i + 1);
            auto rc = pack_packet(header, payload.data(), payload.size(), encoded.data(), encoded.size(), out_len);
            if (!rc.ok()) {
                std::printf("pack_packet failed: err=%u\n", static_cast<unsigned>(rc.code));
                return 1;
            }
            PacketView view{};
            rc = parse_packet(encoded.data(), out_len, view);
            if (!rc.ok()) {
                std::printf("parse_packet failed: err=%u\n", static_cast<unsigned>(rc.code));
                return 1;
            }
        }
        print_alloc_profile("packet hot path", kIterations);
    }

    {
        ReliabilityConfig cfg{};
        cfg.max_pending_messages = static_cast<U32>(kIterations + 1);
        cfg.max_pending_bytes = 1024 * 1024;
        ReliableSession session{};
        session.configure(cfg);
        std::array<U8, 64> payload{};

        reset_alloc_counters();
        for (std::size_t i = 0; i < kIterations; ++i) {
            PendingReliableMessage pending{};
            auto rc = session.enqueue(1,
                                      payload.data(),
                                      static_cast<U16>(payload.size()),
                                      SendPriority::Normal,
                                      0,
                                      1,
                                      pending);
            if (!rc.ok()) {
                std::printf("enqueue failed: err=%u\n", static_cast<unsigned>(rc.code));
                return 1;
            }
            (void)session.acknowledge(pending.message_id, 2);
        }
        print_alloc_profile("reliable enqueue+ack", kIterations);
    }

    {
        FragmentReassembler reassembler{};
        FragmentationConfig cfg{};
        reassembler.configure(cfg);
        std::vector<U8> payload(4096, 0x5A);

        reset_alloc_counters();
        for (std::size_t i = 0; i < kIterations; ++i) {
            const U16 count = fragment_count_for_length(static_cast<U16>(payload.size()));
            for (U16 index = 0; index < count; ++index) {
                std::vector<U8> encoded(NetConfig::MaxEncryptedPlaintextBytes, 0);
                ByteWriter writer{ encoded.data(), encoded.size() };
                const U16 len = fragment_size_for_index(static_cast<U16>(payload.size()), index);
                const ST offset = static_cast<ST>(index) * NetConfig::MaxFragmentDataBytes;
                auto rc = write_fragment_payload(writer,
                                                 static_cast<U64>(i + 1),
                                                 1,
                                                 Channel::ReliableOrdered,
                                                 3,
                                                 index,
                                                 count,
                                                 static_cast<U16>(payload.size()),
                                                 payload.data() + offset,
                                                 len);
                if (!rc.ok()) {
                    std::printf("write_fragment_payload failed: err=%u\n", static_cast<unsigned>(rc.code));
                    return 1;
                }
                encoded.resize(writer.off);

                ByteReader reader{ encoded.data(), encoded.size() };
                FragmentView fragment{};
                rc = read_fragment_payload(reader, fragment);
                if (!rc.ok()) {
                    std::printf("read_fragment_payload failed: err=%u\n", static_cast<unsigned>(rc.code));
                    return 1;
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
                    return 1;
                }
            }
            reassembler.clear();
        }
        print_alloc_profile("fragment reassembly", kIterations);
    }

    return 0;
}
