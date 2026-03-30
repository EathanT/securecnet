#pragma once
#include "securecnet/platform.hpp"
<<<<<<< HEAD
#include "securecnet/util/util.h"
=======
#include "util/util.h"
>>>>>>> origin/main
#include <string>

namespace scn {

    struct Endpoint {
        sockaddr_storage addr{};
        socklen_t len{ 0 };

        std::string to_string() const;
        U16 port() const;
    };

} 