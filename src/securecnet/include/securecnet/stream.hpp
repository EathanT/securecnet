#pragma once

#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"
#include "securecnet/result.hpp"

#include <span>
#include <vector>

namespace scn {

    static constexpr U8 StreamFlagFin = 0x01;

    struct StreamFrameView {
        U16 stream_id{ 0 };
        U8 flags{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };
    };

    constexpr U16 stream_frame_header_bytes() {
        return static_cast<U16>(sizeof(U16) + sizeof(U8) + sizeof(U16));
    }

    constexpr U16 max_stream_frame_payload() {
        return static_cast<U16>(NetConfig::MaxOrderedMessageBytes - stream_frame_header_bytes());
    }

    inline Result write_stream_frame(ByteWriter& w, U16 stream_id, U8 flags, const void* data, U16 len) {
        if (stream_id == 0) {
            return Result::fail(Errc::InvalidArg, "stream_id must be non-zero");
        }
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "stream frame data is null");
        }
        if (len > max_stream_frame_payload()) {
            return Result::fail(Errc::TooLarge, "stream frame payload exceeds ordered channel budget");
        }
        Result rc = w.write_u16(stream_id);
        if (!rc.ok()) return rc;
        rc = w.write_u8(flags);
        if (!rc.ok()) return rc;
        rc = w.write_u16(len);
        if (!rc.ok()) return rc;
        if (len > 0) {
            rc = w.write_bytes(data, len);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_stream_frame(ByteReader& r, StreamFrameView& view) {
        view = {};
        Result rc = r.read_u16(view.stream_id);
        if (!rc.ok()) return rc;
        rc = r.read_u8(view.flags);
        if (!rc.ok()) return rc;
        rc = r.read_u16(view.len);
        if (!rc.ok()) return rc;
        if (view.stream_id == 0) {
            return Result::fail(Errc::BadPacket, "stream_id must be non-zero");
        }
        if (view.len > max_stream_frame_payload()) {
            return Result::fail(Errc::BadPacket, "stream frame payload exceeds ordered channel budget");
        }
        if (r.remaining() < view.len) {
            return Result::fail(Errc::Truncated, "truncated stream frame payload");
        }
        view.data = (view.len > 0) ? r.peek_ptr(view.len) : nullptr;
        rc = r.skip(view.len);
        if (!rc.ok()) return rc;
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in stream frame");
        }
        return Result::success();
    }

    template <class Fn>
    Result chunk_stream_bytes(U16 stream_id, std::span<const U8> bytes, Fn&& emit, U8 final_flags = StreamFlagFin) {
        if (stream_id == 0) {
            return Result::fail(Errc::InvalidArg, "stream_id must be non-zero");
        }
        const U16 chunk_limit = max_stream_frame_payload();
        ST offset = 0;
        while (offset < bytes.size()) {
            const ST remaining = bytes.size() - offset;
            const U16 chunk_len = static_cast<U16>(remaining > chunk_limit ? chunk_limit : remaining);
            const bool is_last = (offset + chunk_len) == bytes.size();

            std::array<U8, NetConfig::MaxOrderedMessageBytes> encoded{};
            ByteWriter writer{ encoded.data(), encoded.size() };
            auto rc = write_stream_frame(writer,
                                         stream_id,
                                         is_last ? final_flags : 0,
                                         bytes.data() + offset,
                                         chunk_len);
            if (!rc.ok()) {
                return rc;
            }
            rc = emit(std::span<const U8>(encoded.data(), writer.off), is_last);
            if (!rc.ok()) {
                return rc;
            }
            offset += chunk_len;
        }
        if (bytes.empty()) {
            std::array<U8, stream_frame_header_bytes()> encoded{};
            ByteWriter writer{ encoded.data(), encoded.size() };
            auto rc = write_stream_frame(writer, stream_id, final_flags, nullptr, 0);
            if (!rc.ok()) {
                return rc;
            }
            return emit(std::span<const U8>(encoded.data(), writer.off), true);
        }
        return Result::success();
    }

    class StreamReceiveBuffer {
    public:
        Result append(const StreamFrameView& frame) {
            if (_stream_id == 0) {
                _stream_id = frame.stream_id;
            } else if (_stream_id != frame.stream_id) {
                return Result::fail(Errc::BadPacket, "mixed stream ids in receive buffer");
            }
            if (_finished) {
                return Result::fail(Errc::StateError, "stream already finished");
            }
            if ((_bytes.size() + frame.len) > static_cast<ST>(U32_MAX)) {
                return Result::fail(Errc::TooLarge, "stream receive buffer exceeded maximum size");
            }
            if (frame.len > 0 && frame.data) {
                _bytes.insert(_bytes.end(), frame.data, frame.data + frame.len);
            }
            if ((frame.flags & StreamFlagFin) != 0) {
                _finished = true;
            }
            return Result::success();
        }

        void clear() {
            _stream_id = 0;
            _finished = false;
            _bytes.clear();
        }

        U16 stream_id() const { return _stream_id; }
        bool finished() const { return _finished; }
        std::span<const U8> bytes() const { return std::span<const U8>(_bytes.data(), _bytes.size()); }

    private:
        U16 _stream_id{ 0 };
        bool _finished{ false };
        std::vector<U8> _bytes{};
    };

} // namespace scn
