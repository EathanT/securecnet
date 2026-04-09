#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>


using I8 = std::int8_t;
using U8 = std::uint8_t;
using I16 = std::int16_t;
using U16 = std::uint16_t;
using I32 = std::int32_t;
using U32 = std::uint32_t;
using I64 = std::int64_t;
using U64 = std::uint64_t;
using UPtr = std::uintptr_t;
using Byte = U8;
using F32 = float;
using F64 = double;
using B8 = U8;
using B32 = U32;
using Flags32 = U32;
using Flags16 = U16;
using Flags8 = U8;
using ST = std::size_t;

#define U8_MAX 0xFF
#define U16_MAX 0xFFFF
#define U32_MAX 0xFFFFFFFF
#define U64_MAX 0xFFFFFFFFFFFFFFFFULL
#define I8_MAX 0x7F
#define I16_MAX 0x7FFF
#define I32_MAX 0x7FFFFFFF
#define I64_MAX 0x7FFFFFFFFFFFFFFFULL
#define I8_MIN I8(0x80)
#define I16_MIN I16(0x8000)
#define I32_MIN I32(0x80000000)
#define I64_MIN I64(0x8000000000000000LL)
#define F32_SMALL (std::bit_cast<F32>(0x00800000u))
#define F32_LARGE (std::bit_cast<F32>(0x7F7FFFFFu))
#define F32_INF (std::bit_cast<F32>(0x7F800000u))
#define F32_QNAN (std::bit_cast<F32>(0x7FFFFFFFu))
#define F32_SNAN (std::bit_cast<F32>(0x7FBFFFFFu))
#define F64_SMALL (std::bit_cast<F64>(0x0010000000000000ull))
#define F64_LARGE (std::bit_cast<F64>(0x7FEFFFFFFFFFFFFFull))
#define F64_INF (std::bit_cast<F64>(0x7FF0000000000000ull))
#define F64_QNAN (std::bit_cast<F64>(0x7FFFFFFFFFFFFFFFull))
#define F64_SNAN (std::bit_cast<F64>(0x7FF7FFFFFFFFFFFFull))
#define B32_TRUE 1
#define B32_FALSE 0
#define B8_TRUE 1
#define B8_FALSE 0

