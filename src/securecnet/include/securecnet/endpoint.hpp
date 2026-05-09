#pragma once
#include "securecnet/platform.hpp"
#include "securecnet/util/util.h"
#include <cstddef>
#include <functional>
#include <string>

namespace scn {

    struct Endpoint {
        sockaddr_storage addr{};
        socklen_t len{ 0 };

        std::string to_string() const;
        U16 port() const;
    };

    bool operator==(const Endpoint& lhs, const Endpoint& rhs);
    bool operator!=(const Endpoint& lhs, const Endpoint& rhs);

    struct EndpointHash {
        std::size_t operator()(const Endpoint& endpoint) const noexcept;
    };

}
