#include "securecnet/address.hpp"
#include "securecnet/platform.hpp"
#include <cstring>
#include <string>


namespace scn {

    Result resolve_endpoints(std::string_view host, std::string_view port,
                             bool passive, std::vector<Endpoint>& out)
    {
        out.clear();

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_flags = passive ? AI_PASSIVE : 0;

        std::string port_s(port.begin(), port.end());

        auto is_digits = [](const std::string& s) {
            if (s.empty()) return false;
            for (char c : s) {
                if (c < '0' || c > '9') return false;
            }
            return true;
        };

        if (is_digits(port_s)) {
            hints.ai_flags |= AI_NUMERICSERV;
        }

        // getaddrinfo expects null-terminated C strings
        hints.ai_flags = passive ? AI_PASSIVE : 0;

        std::string host_s;
        const char* node = nullptr;
        if (!host.empty()) {
            host_s.assign(host.begin(), host.end());
            node = host_s.c_str();
        }

        addrinfo* res = nullptr;
        const int rc = getaddrinfo(node, port_s.c_str(), &hints, &res);

        if (rc != 0) {
#ifdef _WIN32
            return Result::fail(Errc::ResolveError, gai_strerrorA(rc));
#else
            return Result::fail(Errc::ResolveError, gai_strerror(rc));
#endif
        }
        if (!res) {
            return Result::fail(Errc::ResolveError, "getaddrinfo returned null");
        }
            
        
        

        for (addrinfo* p = res; p; p = p->ai_next) {
            Endpoint ep{};
            std::memcpy(&ep.addr, p->ai_addr, p->ai_addrlen);
            ep.len = static_cast<socklen_t>(p->ai_addrlen);
            out.push_back(ep);
        }

        freeaddrinfo(res);
        return Result::success();
    }

}
