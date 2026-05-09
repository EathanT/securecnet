#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>

#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"
#include "securecnet/message.hpp"
#include "securecnet/result.hpp"

namespace scn {

    struct FragmentView {
        U64 message_id{ 0 };
        U64 delivery_sequence{ 0 };
        Channel channel{ Channel::Unreliable };
        U8 type{ 0 };
        U16 fragment_index{ 0 };
        U16 fragment_count{ 0 };
        U16 original_length{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };
    };

    struct FragmentedMessage {
        U64 message_id{ 0 };
        U64 delivery_sequence{ 0 };
        Channel channel{ Channel::Unreliable };
        U8 type{ 0 };
        std::vector<U8> payload{};
    };

    constexpr U16 fragment_count_for_length(U16 original_length) {
        return (original_length == 0)
            ? 0
            : static_cast<U16>((original_length + NetConfig::MaxFragmentDataBytes - 1) / NetConfig::MaxFragmentDataBytes);
    }

    constexpr U16 fragment_size_for_index(U16 original_length, U16 fragment_index) {
        const U16 count = fragment_count_for_length(original_length);
        if (count == 0 || fragment_index >= count) {
            return 0;
        }
        const U16 offset = static_cast<U16>(fragment_index * NetConfig::MaxFragmentDataBytes);
        const U16 remaining = static_cast<U16>(original_length - offset);
        return static_cast<U16>((std::min<U16>)(remaining, NetConfig::MaxFragmentDataBytes));
    }

    inline Result write_fragment_payload(ByteWriter& w,
                                         U64 message_id,
                                         U64 delivery_sequence,
                                         Channel channel,
                                         U8 type,
                                         U16 fragment_index,
                                         U16 fragment_count,
                                         U16 original_length,
                                         const void* data,
                                         U16 len) {
        if (message_id == 0) {
            return Result::fail(Errc::InvalidArg, "fragment message_id must be non-zero");
        }
        if (!channel_is_application(channel)) {
            return Result::fail(Errc::InvalidArg, "fragment channel must be an application channel");
        }
        if (original_length == 0) {
            return Result::fail(Errc::InvalidArg, "fragment original length is invalid");
        }
        const U16 expected_count = fragment_count_for_length(original_length);
        if (fragment_count == 0 || fragment_count != expected_count) {
            return Result::fail(Errc::InvalidArg, "fragment count does not match original length");
        }
        if (fragment_index >= fragment_count) {
            return Result::fail(Errc::InvalidArg, "fragment index out of range");
        }
        const U16 expected_len = fragment_size_for_index(original_length, fragment_index);
        if (len != expected_len) {
            return Result::fail(Errc::InvalidArg, "fragment length does not match index/original length");
        }
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "fragment data is null");
        }

        Result rc = w.write_u64(message_id);
        if (!rc.ok()) return rc;
        rc = w.write_u64(delivery_sequence);
        if (!rc.ok()) return rc;
        rc = w.write_u8(static_cast<U8>(channel));
        if (!rc.ok()) return rc;
        rc = w.write_u8(type);
        if (!rc.ok()) return rc;
        rc = w.write_u16(fragment_index);
        if (!rc.ok()) return rc;
        rc = w.write_u16(fragment_count);
        if (!rc.ok()) return rc;
        rc = w.write_u16(original_length);
        if (!rc.ok()) return rc;
        if (len > 0) {
            rc = w.write_bytes(data, len);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_fragment_payload(ByteReader& r, FragmentView& out) {
        out = {};
        if (r.remaining() < static_cast<ST>(NetConfig::FragmentHeaderBytes)) {
            return Result::fail(Errc::BadPacket, "fragment payload truncated");
        }
        U8 raw_channel = 0;
        Result rc = r.read_u64(out.message_id);
        if (!rc.ok()) return rc;
        rc = r.read_u64(out.delivery_sequence);
        if (!rc.ok()) return rc;
        rc = r.read_u8(raw_channel);
        if (!rc.ok()) return rc;
        rc = r.read_u8(out.type);
        if (!rc.ok()) return rc;
        rc = r.read_u16(out.fragment_index);
        if (!rc.ok()) return rc;
        rc = r.read_u16(out.fragment_count);
        if (!rc.ok()) return rc;
        rc = r.read_u16(out.original_length);
        if (!rc.ok()) return rc;

        if (out.message_id == 0 || raw_channel > static_cast<U8>(Channel::SequencedUnreliable)) {
            return Result::fail(Errc::BadPacket, "fragment metadata is invalid");
        }
        out.channel = static_cast<Channel>(raw_channel);
        if (out.fragment_count == 0 || out.fragment_index >= out.fragment_count || out.original_length == 0) {
            return Result::fail(Errc::BadPacket, "fragment fields are inconsistent");
        }
        const U16 expected_count = fragment_count_for_length(out.original_length);
        if (expected_count == 0 || out.fragment_count != expected_count) {
            return Result::fail(Errc::BadPacket, "fragment count does not match original length");
        }
        const U16 expected_len = fragment_size_for_index(out.original_length, out.fragment_index);
        if (expected_len == 0) {
            return Result::fail(Errc::BadPacket, "fragment index is impossible");
        }
        if (r.remaining() != expected_len) {
            return Result::fail(Errc::BadPacket, "fragment payload length is invalid");
        }
        out.len = static_cast<U16>(r.remaining());
        out.data = (out.len == 0) ? nullptr : r.peek_ptr(out.len);
        return r.skip(out.len);
    }

    class FragmentReassembler {
    public:
        void configure(const FragmentationConfig& cfg) {
            _cfg = cfg;
            clear();
        }

        template <class CompleteFn>
        Result accept(U64 now_ms, const FragmentView& fragment, CompleteFn&& on_complete,
                      bool& duplicate, bool& completed) {
            duplicate = false;
            completed = false;
            if (!_cfg.enabled) {
                return Result::fail(Errc::StateError, "fragmentation disabled");
            }
            if (fragment.fragment_count > _cfg.max_fragments_per_message ||
                fragment.original_length > _cfg.max_reassembled_message_bytes) {
                return Result::fail(Errc::TooLarge, "fragment exceeds policy");
            }
            if (fragment.fragment_count == 0 || fragment.fragment_index >= fragment.fragment_count) {
                return Result::fail(Errc::BadPacket, "fragment index/count is invalid");
            }
            if (fragment.len != fragment_size_for_index(fragment.original_length, fragment.fragment_index)) {
                return Result::fail(Errc::BadPacket, "fragment length is invalid");
            }
            if (fragment.len > 0 && !fragment.data) {
                return Result::fail(Errc::BadPacket, "fragment data is null");
            }
            if (!channel_is_application(fragment.channel)) {
                return Result::fail(Errc::BadPacket, "fragment channel is invalid");
            }

            auto it = _entries.find(fragment.message_id);
            if (it == _entries.end()) {
                if (_entries.size() >= _cfg.max_concurrent_reassemblies_per_peer) {
                    return Result::fail(Errc::QueueFull, "too many concurrent reassemblies");
                }
                if ((_memory_bytes + fragment.original_length) > _cfg.max_total_reassembly_memory_per_peer) {
                    return Result::fail(Errc::QueueFull, "reassembly memory quota exceeded");
                }

                Entry entry{};
                entry.message_id = fragment.message_id;
                entry.delivery_sequence = fragment.delivery_sequence;
                entry.channel = fragment.channel;
                entry.type = fragment.type;
                entry.fragment_count = fragment.fragment_count;
                entry.original_length = fragment.original_length;
                entry.created_ms = now_ms;
                entry.last_update_ms = now_ms;
                entry.payload.resize(fragment.original_length);
                entry.received.assign(fragment.fragment_count, false);
                auto inserted = _entries.emplace(fragment.message_id, std::move(entry));
                it = inserted.first;
                _memory_bytes += fragment.original_length;
            }

            Entry& entry = it->second;
            if (entry.delivery_sequence != fragment.delivery_sequence ||
                entry.channel != fragment.channel ||
                entry.type != fragment.type ||
                entry.fragment_count != fragment.fragment_count ||
                entry.original_length != fragment.original_length) {
                return Result::fail(Errc::BadPacket, "fragment set metadata mismatch");
            }

            if (entry.received[fragment.fragment_index]) {
                duplicate = true;
                entry.last_update_ms = now_ms;
                return Result::success();
            }

            const ST offset = static_cast<ST>(fragment.fragment_index) * NetConfig::MaxFragmentDataBytes;
            if ((offset + fragment.len) > entry.payload.size()) {
                return Result::fail(Errc::BadPacket, "fragment exceeds reassembly buffer");
            }
            if (fragment.len > 0) {
                std::memcpy(entry.payload.data() + offset, fragment.data, fragment.len);
            }
            entry.received[fragment.fragment_index] = true;
            ++entry.received_count;
            entry.last_update_ms = now_ms;

            if (entry.received_count == entry.fragment_count) {
                FragmentedMessage message{};
                message.message_id = entry.message_id;
                message.delivery_sequence = entry.delivery_sequence;
                message.channel = entry.channel;
                message.type = entry.type;
                message.payload = entry.payload;
                auto rc = on_complete(message);
                if (!rc.ok()) {
                    return rc;
                }
                _memory_bytes -= entry.original_length;
                _entries.erase(it);
                completed = true;
            }
            return Result::success();
        }

        template <class ExpireFn>
        void expire_old(U64 now_ms, ExpireFn&& on_expire) {
            for (auto it = _entries.begin(); it != _entries.end();) {
                const bool expired = now_ms >= (it->second.last_update_ms + _cfg.reassembly_timeout_ms);
                if (!expired) {
                    ++it;
                    continue;
                }
                on_expire(it->first);
                _memory_bytes -= it->second.original_length;
                it = _entries.erase(it);
            }
        }

        bool contains(U64 message_id) const {
            return _entries.find(message_id) != _entries.end();
        }

        void clear() {
            _entries.clear();
            _memory_bytes = 0;
        }

        ST active_count() const {
            return _entries.size();
        }

        U64 memory_bytes() const {
            return _memory_bytes;
        }

    private:
        struct Entry {
            U64 message_id{ 0 };
            U64 delivery_sequence{ 0 };
            Channel channel{ Channel::Unreliable };
            U8 type{ 0 };
            U16 fragment_count{ 0 };
            U16 original_length{ 0 };
            U16 received_count{ 0 };
            U64 created_ms{ 0 };
            U64 last_update_ms{ 0 };
            std::vector<U8> payload{};
            std::vector<bool> received{};
        };

        FragmentationConfig _cfg{};
        std::unordered_map<U64, Entry> _entries{};
        U64 _memory_bytes{ 0 };
    };

} // namespace scn
