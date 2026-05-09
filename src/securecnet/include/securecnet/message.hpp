#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <type_traits>

#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"
#include "securecnet/result.hpp"

namespace scn {

    enum class Channel : U8 {
        Unreliable = 0,
        Reliable = 1,
        ReliableOrdered = 2,
        SequencedUnreliable = 3,
        Control = 4,
    };

    struct SendOptions {
        Channel channel{ Channel::Unreliable };
        SendPriority priority{ SendPriority::Normal };
        U64 lifetime_ms{ 0 };
    };

    struct BackpressureInfo {
        Errc code{ Errc::Ok };
        Channel channel{ Channel::Unreliable };
        U8 type{ 0 };
        ST queued_packets{ 0 };
        ST queued_bytes{ 0 };
        U64 send_budget_bytes{ 0 };
    };

    template <class T>
    constexpr bool binary_message_type_supported_v =
        std::is_trivially_copyable_v<T> &&
        std::is_default_constructible_v<T> &&
        !std::is_pointer_v<T>;

    template <class T>
    std::span<const U8> bytes_of(const T& value) {
        static_assert(binary_message_type_supported_v<T>,
                      "scn::bytes_of requires a trivially copyable, default constructible non-pointer type");
        return std::span<const U8>(reinterpret_cast<const U8*>(&value), sizeof(T));
    }

    constexpr ST max_inline_payload_size(Channel channel) {
        switch (channel) {
        case Channel::Reliable:
            return NetConfig::MaxReliableMessageBytes;
        case Channel::ReliableOrdered:
            return NetConfig::MaxOrderedMessageBytes;
        case Channel::SequencedUnreliable:
            return NetConfig::MaxSequencedMessageBytes;
        case Channel::Unreliable:
        case Channel::Control:
        default:
            return NetConfig::MaxMessageBytes;
        }
    }

    template <class T>
    constexpr bool fits_inline(Channel channel) {
        static_assert(binary_message_type_supported_v<T>,
                      "fits_inline requires a trivially copyable, default constructible non-pointer type");
        return sizeof(T) <= max_inline_payload_size(channel);
    }

    template <class T> constexpr bool fits_unreliable() { return fits_inline<T>(Channel::Unreliable); }
    template <class T> constexpr bool fits_reliable() { return fits_inline<T>(Channel::Reliable); }
    template <class T> constexpr bool fits_ordered() { return fits_inline<T>(Channel::ReliableOrdered); }
    template <class T> constexpr bool fits_latest() { return fits_inline<T>(Channel::SequencedUnreliable); }

    struct MsgView {
        Channel channel{};
        U8 type{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };

        std::span<const U8> bytes() const {
            if (!data || len == 0) {
                return {};
            }
            return std::span<const U8>(data, len);
        }

        std::span<const U8> u8span() const {
            return bytes();
        }

        std::span<const std::byte> byte_span() const {
            if (!data || len == 0) {
                return {};
            }
            return std::span<const std::byte>(reinterpret_cast<const std::byte*>(data), len);
        }

        template <class T>
        ResultT<T> as() const {
            static_assert(binary_message_type_supported_v<T>,
                          "MsgView::as requires a trivially copyable, default constructible non-pointer type");
            if (len != sizeof(T)) {
                return ResultT<T>::fail(Errc::BadPacket, "binary message size mismatch");
            }
            if (len > 0 && !data) {
                return ResultT<T>::fail(Errc::BadPacket, "binary message data is null");
            }
            T value{};
            if constexpr (sizeof(T) > 0) {
                std::memcpy(&value, data, sizeof(T));
            }
            return ResultT<T>::success(value);
        }

        std::string_view text() const {
            if (!data || len == 0) {
                return {};
            }
            return std::string_view(reinterpret_cast<const char*>(data), len);
        }
    };

    constexpr bool channel_is_reliable(Channel channel) {
        return channel == Channel::Reliable || channel == Channel::ReliableOrdered;
    }

    constexpr bool channel_valid(Channel channel) {
        return channel == Channel::Unreliable ||
               channel == Channel::Reliable ||
               channel == Channel::ReliableOrdered ||
               channel == Channel::SequencedUnreliable ||
               channel == Channel::Control;
    }

    constexpr bool channel_is_application(Channel channel) {
        return channel_valid(channel) && channel != Channel::Control;
    }

    constexpr bool channel_is_ordered(Channel channel) {
        return channel == Channel::ReliableOrdered;
    }

    constexpr bool channel_is_sequenced(Channel channel) {
        return channel == Channel::SequencedUnreliable;
    }

    constexpr U16 max_inline_payload_for_channel(Channel channel) {
        return static_cast<U16>(max_inline_payload_size(channel));
    }

    // Writes: [ch][type][len][bytes]
    inline Result write_message(ByteWriter& w, Channel ch, U8 type,
                                const void* data, U16 len) {
        if (!channel_valid(ch)) {
            return Result::fail(Errc::InvalidArg, "invalid message channel");
        }
        if (len > static_cast<U16>(NetConfig::MaxMessageBytes)) {
            return Result::fail(Errc::InvalidArg, "message payload too large");
        }
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "message data is null");
        }

        Result rc = w.write_u8(static_cast<U8>(ch));
        if (!rc.ok()) return rc;
        rc = w.write_u8(type);
        if (!rc.ok()) return rc;
        rc = w.write_u16(len);
        if (!rc.ok()) return rc;
        if (len > 0) {
            rc = w.write_bytes(data, len);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_message(ByteReader& r, MsgView& out) {
        out = {};
        if (r.remaining() == 0) {
            return Result::fail(Errc::EndOfStream, "no more messages");
        }
        if (r.remaining() < NetConfig::MessageHeaderBytes) {
            return Result::fail(Errc::BadPacket, "truncated message header");
        }

        U8 ch = 0;
        U8 type = 0;
        U16 len = 0;
        Result rc = r.read_u8(ch);
        if (!rc.ok()) return rc;
        rc = r.read_u8(type);
        if (!rc.ok()) return rc;
        rc = r.read_u16(len);
        if (!rc.ok()) return rc;

        if (ch > static_cast<U8>(Channel::Control)) {
            return Result::fail(Errc::BadPacket, "invalid message channel");
        }
        if (len > r.remaining()) {
            return Result::fail(Errc::BadPacket, "message len exceeds payload");
        }

        out.channel = static_cast<Channel>(ch);
        out.type = type;
        out.len = len;
        out.data = (len == 0) ? nullptr : r.peek_ptr(len);
        return r.skip(len);
    }

} // namespace scn
