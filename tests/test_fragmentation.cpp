#include "securecnet/bytebuf.hpp"
#include "securecnet/fragmentation.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

static std::vector<U8> make_payload(U16 len) {
    std::vector<U8> payload(len);
    for (U16 i = 0; i < len; ++i) {
        payload[i] = static_cast<U8>((i * 17u) % 251u);
    }
    return payload;
}

static Result encode_fragment(const std::vector<U8>& payload,
                              U64 message_id,
                              U64 delivery_sequence,
                              Channel channel,
                              U8 type,
                              U16 fragment_index,
                              std::vector<U8>& out) {
    const U16 fragment_count = fragment_count_for_length(static_cast<U16>(payload.size()));
    const U16 fragment_len = fragment_size_for_index(static_cast<U16>(payload.size()), fragment_index);
    const ST offset = static_cast<ST>(fragment_index) * NetConfig::MaxFragmentDataBytes;

    out.assign(NetConfig::MaxEncryptedPlaintextBytes, 0);
    ByteWriter writer{ out.data(), out.size() };
    auto rc = write_fragment_payload(writer,
                                     message_id,
                                     delivery_sequence,
                                     channel,
                                     type,
                                     fragment_index,
                                     fragment_count,
                                     static_cast<U16>(payload.size()),
                                     payload.data() + offset,
                                     fragment_len);
    if (!rc.ok()) {
        return rc;
    }
    out.resize(writer.off);
    return Result::success();
}

int test_fragmentation() {
    int fails = 0;

    {
        const U16 original_length = static_cast<U16>(NetConfig::MaxFragmentDataBytes + 10);
        auto payload = make_payload(original_length);
        std::vector<U8> bytes{};
        auto rc = encode_fragment(payload, 77, 9, Channel::ReliableOrdered, 42, 1, bytes);
        fails += expect(rc.ok(), "encode_fragment should succeed");

        ByteReader reader{ bytes.data(), bytes.size() };
        FragmentView view{};
        rc = read_fragment_payload(reader, view);
        fails += expect(rc.ok(), "read_fragment_payload should succeed");
        fails += expect(view.message_id == 77, "fragment message_id mismatch");
        fails += expect(view.delivery_sequence == 9, "fragment delivery_sequence mismatch");
        fails += expect(view.channel == Channel::ReliableOrdered, "fragment channel mismatch");
        fails += expect(view.type == 42, "fragment type mismatch");
        fails += expect(view.fragment_index == 1, "fragment index mismatch");
        fails += expect(view.fragment_count == 2, "fragment count mismatch");
        fails += expect(view.original_length == original_length, "fragment original length mismatch");
        fails += expect(view.len == 10, "fragment tail length mismatch");
        fails += expect(std::memcmp(view.data, payload.data() + NetConfig::MaxFragmentDataBytes, view.len) == 0,
                        "fragment bytes mismatch");
    }

    {
        FragmentReassembler reassembler{};
        FragmentationConfig cfg{};
        reassembler.configure(cfg);

        const auto payload = make_payload(static_cast<U16>(NetConfig::MaxFragmentDataBytes + 50));
        std::vector<U8> encoded_a{};
        std::vector<U8> encoded_b{};
        auto rc = encode_fragment(payload, 91, 5, Channel::Reliable, 7, 1, encoded_b);
        fails += expect(rc.ok(), "encode second fragment should succeed");
        rc = encode_fragment(payload, 91, 5, Channel::Reliable, 7, 0, encoded_a);
        fails += expect(rc.ok(), "encode first fragment should succeed");

        ByteReader reader_b{ encoded_b.data(), encoded_b.size() };
        FragmentView view_b{};
        rc = read_fragment_payload(reader_b, view_b);
        fails += expect(rc.ok(), "read second fragment should succeed");

        ByteReader reader_a{ encoded_a.data(), encoded_a.size() };
        FragmentView view_a{};
        rc = read_fragment_payload(reader_a, view_a);
        fails += expect(rc.ok(), "read first fragment should succeed");

        FragmentedMessage completed_message{};
        bool duplicate = false;
        bool completed = false;
        rc = reassembler.accept(100, view_b,
                                [&](const FragmentedMessage& message) {
                                    completed_message = message;
                                    return Result::success();
                                },
                                duplicate, completed);
        fails += expect(rc.ok(), "reassembler should accept out-of-order fragment");
        fails += expect(!duplicate, "first out-of-order fragment should not be duplicate");
        fails += expect(!completed, "reassembly should not complete after one fragment");

        rc = reassembler.accept(101, view_a,
                                [&](const FragmentedMessage& message) {
                                    completed_message = message;
                                    return Result::success();
                                },
                                duplicate, completed);
        fails += expect(rc.ok(), "reassembler should accept final fragment");
        fails += expect(completed, "reassembler should complete after final fragment");
        fails += expect(completed_message.message_id == 91, "reassembled message id mismatch");
        fails += expect(completed_message.delivery_sequence == 5, "reassembled delivery sequence mismatch");
        fails += expect(completed_message.channel == Channel::Reliable, "reassembled channel mismatch");
        fails += expect(completed_message.type == 7, "reassembled type mismatch");
        fails += expect(completed_message.payload == payload, "reassembled payload mismatch");
        fails += expect(reassembler.active_count() == 0, "reassembler should clear completed message state");
    }

    {
        FragmentReassembler reassembler{};
        FragmentationConfig cfg{};
        reassembler.configure(cfg);

        const auto payload = make_payload(static_cast<U16>(NetConfig::MaxFragmentDataBytes + 1));
        std::vector<U8> encoded{};
        auto rc = encode_fragment(payload, 92, 1, Channel::Unreliable, 8, 0, encoded);
        fails += expect(rc.ok(), "encode duplicate fragment should succeed");
        ByteReader reader{ encoded.data(), encoded.size() };
        FragmentView view{};
        rc = read_fragment_payload(reader, view);
        fails += expect(rc.ok(), "read duplicate fragment should succeed");

        bool duplicate = false;
        bool completed = false;
        rc = reassembler.accept(200, view,
                                [&](const FragmentedMessage&) {
                                    return Result::success();
                                },
                                duplicate, completed);
        fails += expect(rc.ok(), "reassembler should accept first fragment instance");
        rc = reassembler.accept(201, view,
                                [&](const FragmentedMessage&) {
                                    return Result::success();
                                },
                                duplicate, completed);
        fails += expect(rc.ok(), "reassembler should accept duplicate fragment cleanly");
        fails += expect(duplicate, "reassembler should mark duplicate fragment");
        fails += expect(!completed, "duplicate fragment should not complete reassembly");
    }

    {
        FragmentReassembler reassembler{};
        FragmentationConfig cfg{};
        reassembler.configure(cfg);

        const auto payload = make_payload(static_cast<U16>(NetConfig::MaxFragmentDataBytes + 20));
        std::vector<U8> encoded{};
        auto rc = encode_fragment(payload, 93, 10, Channel::Unreliable, 9, 0, encoded);
        fails += expect(rc.ok(), "encode expiring fragment should succeed");
        ByteReader reader{ encoded.data(), encoded.size() };
        FragmentView view{};
        rc = read_fragment_payload(reader, view);
        fails += expect(rc.ok(), "read expiring fragment should succeed");

        bool duplicate = false;
        bool completed = false;
        rc = reassembler.accept(300, view,
                                [&](const FragmentedMessage&) {
                                    return Result::success();
                                },
                                duplicate, completed);
        fails += expect(rc.ok(), "reassembler should accept fragment before expiry");

        int expired = 0;
        reassembler.expire_old(300 + cfg.reassembly_timeout_ms,
                               [&](U64) {
                                   ++expired;
                               });
        fails += expect(expired == 1, "reassembler should expire incomplete message");
        fails += expect(reassembler.active_count() == 0, "reassembler should clear expired message");
    }

    {
        FragmentReassembler reassembler{};
        FragmentationConfig cfg{};
        cfg.max_total_reassembly_memory_per_peer = 128;
        reassembler.configure(cfg);

        const auto payload = make_payload(256);
        std::vector<U8> encoded{};
        auto rc = encode_fragment(payload, 94, 1, Channel::Unreliable, 1, 0, encoded);
        fails += expect(rc.ok(), "encode memory-budget fragment should succeed");
        ByteReader reader{ encoded.data(), encoded.size() };
        FragmentView view{};
        rc = read_fragment_payload(reader, view);
        fails += expect(rc.ok(), "read memory-budget fragment should succeed");

        bool duplicate = false;
        bool completed = false;
        rc = reassembler.accept(400, view,
                                [&](const FragmentedMessage&) {
                                    return Result::success();
                                },
                                duplicate, completed);
        fails += expect(!rc.ok() && rc.code == Errc::QueueFull,
                        "reassembler should reject message that exceeds memory budget");
    }

    return fails;
}
