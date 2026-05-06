#pragma once

#include "securecnet/bytebuf.hpp"
#include "securecnet/endpoint.hpp"
#include "securecnet/result.hpp"

#include <array>
#include <cstring>

namespace scn {

    enum class NatHintFamily : U8 {
        IPv4 = 4,
        IPv6 = 6,
    };

    struct NatPeerHint {
        NatHintFamily family{ NatHintFamily::IPv4 };
        U16 port{ 0 };
        std::array<U8, 16> address{};
    };

    struct NatPunchFrame {
        U64 token{ 0 };
        U64 issued_at_ms{ 0 };
    };

    inline Result write_nat_peer_hint(ByteWriter& w, const NatPeerHint& hint) {
        if (hint.port == 0) {
            return Result::fail(Errc::InvalidArg, "nat hint port must be non-zero");
        }
        const U8 family = static_cast<U8>(hint.family);
        if (family != static_cast<U8>(NatHintFamily::IPv4) && family != static_cast<U8>(NatHintFamily::IPv6)) {
            return Result::fail(Errc::InvalidArg, "nat hint family is invalid");
        }
        Result rc = w.write_u8(family);
        if (!rc.ok()) return rc;
        rc = w.write_u16(hint.port);
        if (!rc.ok()) return rc;
        return w.write_bytes(hint.address.data(), hint.address.size());
    }

    inline Result read_nat_peer_hint(ByteReader& r, NatPeerHint& hint) {
        hint = {};
        U8 family = 0;
        Result rc = r.read_u8(family);
        if (!rc.ok()) return rc;
        if (family == static_cast<U8>(NatHintFamily::IPv4)) {
            hint.family = NatHintFamily::IPv4;
        } else if (family == static_cast<U8>(NatHintFamily::IPv6)) {
            hint.family = NatHintFamily::IPv6;
        } else {
            return Result::fail(Errc::BadPacket, "invalid nat hint family");
        }
        rc = r.read_u16(hint.port);
        if (!rc.ok()) return rc;
        if (hint.port == 0) {
            return Result::fail(Errc::BadPacket, "nat hint port must be non-zero");
        }
        rc = r.read_bytes(hint.address.data(), hint.address.size());
        if (!rc.ok()) return rc;
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in nat hint");
        }
        return Result::success();
    }

    inline Result make_nat_peer_hint(const Endpoint& endpoint, NatPeerHint& hint) {
        hint = {};
        if (endpoint.len == 0) {
            return Result::fail(Errc::InvalidArg, "endpoint is empty");
        }
        const sockaddr* sa = reinterpret_cast<const sockaddr*>(&endpoint.addr);
        if (sa->sa_family == AF_INET) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
            hint.family = NatHintFamily::IPv4;
            hint.port = ntohs(in->sin_port);
            std::memcpy(hint.address.data(), &in->sin_addr, 4);
            return Result::success();
        }
        if (sa->sa_family == AF_INET6) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
            hint.family = NatHintFamily::IPv6;
            hint.port = ntohs(in6->sin6_port);
            std::memcpy(hint.address.data(), &in6->sin6_addr, 16);
            return Result::success();
        }
        return Result::fail(Errc::InvalidArg, "unsupported endpoint family");
    }

    inline Result endpoint_from_nat_peer_hint(const NatPeerHint& hint, Endpoint& endpoint) {
        endpoint = {};
        if (hint.port == 0) {
            return Result::fail(Errc::InvalidArg, "nat hint port must be non-zero");
        }
        if (hint.family == NatHintFamily::IPv4) {
            sockaddr_in in{};
            in.sin_family = AF_INET;
            in.sin_port = htons(hint.port);
            std::memcpy(&in.sin_addr, hint.address.data(), 4);
            std::memcpy(&endpoint.addr, &in, sizeof(in));
            endpoint.len = sizeof(in);
            return Result::success();
        }
        if (hint.family == NatHintFamily::IPv6) {
            sockaddr_in6 in6{};
            in6.sin6_family = AF_INET6;
            in6.sin6_port = htons(hint.port);
            std::memcpy(&in6.sin6_addr, hint.address.data(), 16);
            std::memcpy(&endpoint.addr, &in6, sizeof(in6));
            endpoint.len = sizeof(in6);
            return Result::success();
        }
        return Result::fail(Errc::InvalidArg, "nat hint family is invalid");
    }

    inline Result write_nat_punch_frame(ByteWriter& w, const NatPunchFrame& frame) {
        if (frame.token == 0 || frame.issued_at_ms == 0) {
            return Result::fail(Errc::InvalidArg, "nat punch frame fields must be non-zero");
        }
        Result rc = w.write_u64(frame.token);
        if (!rc.ok()) return rc;
        return w.write_u64(frame.issued_at_ms);
    }

    inline Result read_nat_punch_frame(ByteReader& r, NatPunchFrame& frame) {
        frame = {};
        Result rc = r.read_u64(frame.token);
        if (!rc.ok()) return rc;
        rc = r.read_u64(frame.issued_at_ms);
        if (!rc.ok()) return rc;
        if (frame.token == 0 || frame.issued_at_ms == 0) {
            return Result::fail(Errc::BadPacket, "nat punch frame fields must be non-zero");
        }
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in nat punch frame");
        }
        return Result::success();
    }

} // namespace scn
