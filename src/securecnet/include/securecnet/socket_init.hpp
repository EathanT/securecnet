#pragma once
#include "securecnet/result.hpp"

namespace scn {

    class SocketInit {
    public:
        SocketInit();
        ~SocketInit();

        SocketInit(const SocketInit&) = delete;
        SocketInit& operator=(const SocketInit&) = delete;

        Result status() const { return _status; }

    private:
        Result _status{};

    #ifdef _WIN32
        bool _started{ false };
    #endif

    };

}