#include "securecnet/endpoint.hpp"
#include <cstring>

namespace scn {

    static const void* get_in_addr(const sockaddr* sa) {
        if (sa->sa_family == AF_INET)
            return &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr;

        return &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr;
    }

    U16 Endpoint::port() const {
        const sockaddr* sa = reinterpret_cast<const sockaddr*>(&addr);
        if (len == 0) {
            return 0;
        }

        if (sa->sa_family == AF_INET)
            return ntohs(reinterpret_cast<const sockaddr_in*>(sa)->sin_port);

        if (sa->sa_family == AF_INET6)
            return ntohs(reinterpret_cast<const sockaddr_in6*>(sa)->sin6_port);

        return 0;
    }

    std::string Endpoint::to_string() const {
        const sockaddr* sa = reinterpret_cast<const sockaddr*>(&addr);

        if (len == 0 || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)) {
            return "<uninitialized>:0";
        }

        char ipstr[INET6_ADDRSTRLEN]{};
        if (!inet_ntop(sa->sa_family, get_in_addr(sa), ipstr, sizeof(ipstr))) {
            return std::string("<invalid>:") + std::to_string(port());
        }

        if (sa->sa_family == AF_INET6) {
            return std::string("[") + ipstr + "]:" + std::to_string(port());
        }

        return std::string(ipstr) + ":" + std::to_string(port());
    }

}
