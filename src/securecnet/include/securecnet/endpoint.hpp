#pragma once
#include "securecnet/platform.hpp"
#include "securecnet/util/util.h"
#include <string>

namespace scn {

    struct Endpoint {
        sockaddr_storage addr{};
        socklen_t len{ 0 };

        std::string to_string() const;
        U16 port() const;
    };

}
