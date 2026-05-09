#pragma once

#include <string_view>
#include <utility>

#include "securecnet/util/util.h"

namespace scn {

    enum class Errc : U32 {
        Ok = 0,
        InvalidArg,
        SocketError,
        ResolveError,
        WouldBlock,
        Truncated,
        BadPacket,
        Internal,
        EndOfStream,
        QueueFull,
        UnsupportedVersion,
        AuthFailed,
        Timeout,
        Closed,
        StateError,
        Replay,
        ProtocolError,
        TooLarge,
        RateLimited,
        Backpressure,
    };

    constexpr std::string_view errc_name(Errc code) {
        switch (code) {
        case Errc::Ok: return "Ok";
        case Errc::InvalidArg: return "InvalidArg";
        case Errc::SocketError: return "SocketError";
        case Errc::ResolveError: return "ResolveError";
        case Errc::WouldBlock: return "WouldBlock";
        case Errc::Truncated: return "Truncated";
        case Errc::BadPacket: return "BadPacket";
        case Errc::Internal: return "Internal";
        case Errc::EndOfStream: return "EndOfStream";
        case Errc::QueueFull: return "QueueFull";
        case Errc::UnsupportedVersion: return "UnsupportedVersion";
        case Errc::AuthFailed: return "AuthFailed";
        case Errc::Timeout: return "Timeout";
        case Errc::Closed: return "Closed";
        case Errc::StateError: return "StateError";
        case Errc::Replay: return "Replay";
        case Errc::ProtocolError: return "ProtocolError";
        case Errc::TooLarge: return "TooLarge";
        case Errc::RateLimited: return "RateLimited";
        case Errc::Backpressure: return "Backpressure";
        }
        return "Unknown";
    }

    struct Result {
        Errc code{ Errc::Ok };
        std::string_view msg{};

        constexpr bool ok() const {
            return code == Errc::Ok;
        }

        constexpr explicit operator bool() const {
            return ok();
        }

        constexpr std::string_view name() const {
            return errc_name(code);
        }

        static constexpr Result success() {
            return {};
        }

        static constexpr Result fail(Errc c, std::string_view m = {}) {
            return { c, m };
        }
    };

    template <class T>
    struct ResultT {
        T value{};
        Errc code{ Errc::Ok };
        std::string_view msg{};

        constexpr bool ok() const {
            return code == Errc::Ok;
        }

        constexpr explicit operator bool() const {
            return ok();
        }

        constexpr std::string_view name() const {
            return errc_name(code);
        }

        constexpr Result result() const {
            return { code, msg };
        }

        static constexpr ResultT success(T v) {
            return { std::move(v), Errc::Ok, {} };
        }

        static constexpr ResultT fail(Errc c, std::string_view m = {}) {
            return { T{}, c, m };
        }
    };

} // namespace scn
