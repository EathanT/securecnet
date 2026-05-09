#pragma once

#include <limits>
#include <span>
#include <string_view>
#include <vector>

#include "securecnet/bytebuf.hpp"
#include "securecnet/message.hpp"

namespace scn {

    class BinaryWriter {
    public:
        explicit BinaryWriter(std::span<U8> out) : _writer(out.data(), out.size()) {}
        BinaryWriter(U8* out, ST cap) : _writer(out, cap) {}

        Result u8(U8 value) { return _writer.write_u8(value); }
        Result i8(I8 value) { return _writer.write_u8(static_cast<U8>(value)); }
        Result u16(U16 value) { return _writer.write_u16(value); }
        Result i16(I16 value) { return _writer.write_u16(static_cast<U16>(value)); }
        Result u32(U32 value) { return _writer.write_u32(value); }
        Result i32(I32 value) { return _writer.write_u32(static_cast<U32>(value)); }
        Result u64(U64 value) { return _writer.write_u64(value); }
        Result i64(I64 value) { return _writer.write_u64(static_cast<U64>(value)); }

        Result bytes(std::span<const U8> value) {
            return _writer.write_bytes(value.data(), value.size());
        }

        Result bytes(const void* data, ST len) {
            return _writer.write_bytes(data, len);
        }

        Result sized_bytes(std::span<const U8> value) {
            if (value.size() > static_cast<ST>((std::numeric_limits<U16>::max)())) {
                return Result::fail(Errc::TooLarge, "sized byte payload too large");
            }
            auto rc = _writer.write_u16(static_cast<U16>(value.size()));
            if (!rc.ok()) return rc;
            return bytes(value);
        }

        Result string(std::string_view value) {
            return sized_bytes(std::span<const U8>(reinterpret_cast<const U8*>(value.data()), value.size()));
        }

        template <class T>
        Result pod(const T& value) {
            return bytes(bytes_of(value));
        }

        ST size() const { return _writer.off; }
        ST remaining() const { return _writer.remaining(); }
        const ByteWriter& raw() const { return _writer; }
        ByteWriter& raw() { return _writer; }

    private:
        ByteWriter _writer{};
    };

    class BinaryReader {
    public:
        explicit BinaryReader(std::span<const U8> input) : _reader(input.data(), input.size()) {}
        explicit BinaryReader(const MsgView& msg) : _reader(msg.data, msg.len) {}
        BinaryReader(const U8* input, ST len) : _reader(input, len) {}

        Result u8(U8& value) { return _reader.read_u8(value); }
        Result i8(I8& value) {
            U8 tmp{};
            auto rc = _reader.read_u8(tmp);
            if (!rc.ok()) return rc;
            value = static_cast<I8>(tmp);
            return Result::success();
        }
        Result u16(U16& value) { return _reader.read_u16(value); }
        Result i16(I16& value) {
            U16 tmp{};
            auto rc = _reader.read_u16(tmp);
            if (!rc.ok()) return rc;
            value = static_cast<I16>(tmp);
            return Result::success();
        }
        Result u32(U32& value) { return _reader.read_u32(value); }
        Result i32(I32& value) {
            U32 tmp{};
            auto rc = _reader.read_u32(tmp);
            if (!rc.ok()) return rc;
            value = static_cast<I32>(tmp);
            return Result::success();
        }
        Result u64(U64& value) { return _reader.read_u64(value); }
        Result i64(I64& value) {
            U64 tmp{};
            auto rc = _reader.read_u64(tmp);
            if (!rc.ok()) return rc;
            value = static_cast<I64>(tmp);
            return Result::success();
        }

        Result bytes(void* dst, ST len) {
            return _reader.read_bytes(dst, len);
        }

        Result sized_bytes(std::vector<U8>& out) {
            U16 len{};
            auto rc = _reader.read_u16(len);
            if (!rc.ok()) return rc;
            out.resize(len);
            return _reader.read_bytes(out.empty() ? nullptr : out.data(), out.size());
        }

        ResultT<std::string_view> string_view() {
            U16 len{};
            auto rc = _reader.read_u16(len);
            if (!rc.ok()) {
                return ResultT<std::string_view>::fail(rc.code, rc.msg);
            }
            const U8* ptr = _reader.peek_ptr(len);
            if (len > 0 && !ptr) {
                return ResultT<std::string_view>::fail(Errc::Truncated, "truncated string payload");
            }
            rc = _reader.skip(len);
            if (!rc.ok()) {
                return ResultT<std::string_view>::fail(rc.code, rc.msg);
            }
            return ResultT<std::string_view>::success(
                std::string_view(reinterpret_cast<const char*>(ptr), len));
        }

        template <class T>
        ResultT<T> pod() {
            static_assert(binary_message_type_supported_v<T>,
                          "BinaryReader::pod requires a trivially copyable, default constructible non-pointer type");
            T value{};
            auto rc = _reader.read_bytes(&value, sizeof(T));
            if (!rc.ok()) {
                return ResultT<T>::fail(rc.code, rc.msg);
            }
            return ResultT<T>::success(value);
        }

        ST remaining() const { return _reader.remaining(); }
        const ByteReader& raw() const { return _reader; }
        ByteReader& raw() { return _reader; }

    private:
        ByteReader _reader{};
    };

} // namespace scn
