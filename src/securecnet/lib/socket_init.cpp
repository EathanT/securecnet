#include "securecnet/socket_init.hpp"

#ifdef _WIN32
#include "securecnet/platform.hpp"
#endif

namespace scn {

    SocketInit::SocketInit() {
#ifdef _WIN32
        WSADATA wsa{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
 
        if (rc != 0) {
            _status = Result::fail(Errc::SocketError, "WSAStartup failed");
            return;
        }
        _started = true;
#endif
        _status = Result::success();
    }

    SocketInit::~SocketInit() {
#ifdef _WIN32
        if (_started) WSACleanup();
#endif
    }
} 