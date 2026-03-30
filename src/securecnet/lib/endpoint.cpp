#include "securecnet/endpoint.hpp"
#include <cstring>

namespace scn {

    static void* get_in_addr(sockaddr* sa) {
        if (sa->sa_family == AF_INET)
            return &(((sockaddr_in*)sa)->sin_addr);
        
        return &(((sockaddr_in6*)sa)->sin6_addr);
    }

    U16 Endpoint::port() const {
        const sockaddr* sa = (const sockaddr*)&addr;
        if (sa->sa_family == AF_INET)
            return ntohs(((const sockaddr_in*)sa)->sin_port);
        
        return ntohs(((const sockaddr_in6*)sa)->sin6_port);
    }

    std::string Endpoint::to_string() const {
<<<<<<< HEAD
        const sockaddr* sa = reinterpret_cast<const sockaddr*>(&addr);

        if (len == 0 (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)) {
            return "<uninitialzied>:0";
        }
       
        char ipstr[INET6_ADDRSTRLEN]{};
        const void* src = (sa->sa_family == AF_INET)
            ? static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(sa)->sin_addr)
			: static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr);


        if (!inet_ntop(sa->sa_family, src, ipstr, sizeof(ipstr))) {
            return "<invalid>:" + std::to_string(port());
=======
        char ipstr[INET6_ADDRSTRLEN]{};
        const sockaddr* sa = (const sockaddr*)&addr;
       
        if (!inet_ntop(sa->sa_family, get_in_addr((sockaddr*)sa), ipstr, sizeof(ipstr))) {
            std::strncpy(ipstr, "<invalid>", sizeof(ipstr) - 1);
            ipstr[sizeof(ipstr) - 1] = '\0';
>>>>>>> origin/main
            
        }

        return std::string(ipstr) + ":" + std::to_string(port());
    }

} 