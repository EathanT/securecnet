#pragma once

#include <string_view>

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

    struct Result {
        Errc code{ Errc::Ok };
        std::string_view msg{};

        constexpr bool ok() const {
            return code == Errc::Ok;
        }

        static constexpr Result success() {
            return {};
        }

        static constexpr Result fail(Errc c, std::string_view m = {}) {
            return { c, m };
        }
    };

} // namespace scn
