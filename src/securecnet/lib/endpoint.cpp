#include "securecnet/endpoint.hpp"
#include <cstring>
#include <cstddef>

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


namespace scn {

    bool operator==(const Endpoint& lhs, const Endpoint& rhs) {
        if (lhs.len == 0 || rhs.len == 0) {
            return lhs.len == rhs.len;
        }

        const auto* la = reinterpret_cast<const sockaddr*>(&lhs.addr);
        const auto* ra = reinterpret_cast<const sockaddr*>(&rhs.addr);
        if (la->sa_family != ra->sa_family) {
            return false;
        }

        if (la->sa_family == AF_INET) {
            const auto* l4 = reinterpret_cast<const sockaddr_in*>(la);
            const auto* r4 = reinterpret_cast<const sockaddr_in*>(ra);
            return l4->sin_port == r4->sin_port &&
                   std::memcmp(&l4->sin_addr, &r4->sin_addr, sizeof(in_addr)) == 0;
        }

        if (la->sa_family == AF_INET6) {
            const auto* l6 = reinterpret_cast<const sockaddr_in6*>(la);
            const auto* r6 = reinterpret_cast<const sockaddr_in6*>(ra);
            return l6->sin6_port == r6->sin6_port &&
                   l6->sin6_scope_id == r6->sin6_scope_id &&
                   std::memcmp(&l6->sin6_addr, &r6->sin6_addr, sizeof(in6_addr)) == 0;
        }

        return lhs.len == rhs.len && std::memcmp(&lhs.addr, &rhs.addr, lhs.len) == 0;
    }

    bool operator!=(const Endpoint& lhs, const Endpoint& rhs) {
        return !(lhs == rhs);
    }

    namespace {
        void hash_combine(std::size_t& seed, std::size_t value) noexcept {
            seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U);
        }
    }

    std::size_t EndpointHash::operator()(const Endpoint& endpoint) const noexcept {
        if (endpoint.len == 0) {
            return 0;
        }

        const auto* sa = reinterpret_cast<const sockaddr*>(&endpoint.addr);
        std::size_t seed = std::hash<int>{}(sa->sa_family);
        if (sa->sa_family == AF_INET) {
            const auto* v4 = reinterpret_cast<const sockaddr_in*>(sa);
            hash_combine(seed, std::hash<U16>{}(ntohs(v4->sin_port)));
            hash_combine(seed, std::hash<U32>{}(v4->sin_addr.s_addr));
            return seed;
        }
        if (sa->sa_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(sa);
            hash_combine(seed, std::hash<U16>{}(ntohs(v6->sin6_port)));
            hash_combine(seed, std::hash<U32>{}(v6->sin6_scope_id));
            const auto* bytes = reinterpret_cast<const U8*>(&v6->sin6_addr);
            for (ST i = 0; i < sizeof(in6_addr); ++i) {
                hash_combine(seed, std::hash<U8>{}(bytes[i]));
            }
            return seed;
        }

        const auto* bytes = reinterpret_cast<const U8*>(&endpoint.addr);
        for (socklen_t i = 0; i < endpoint.len; ++i) {
            hash_combine(seed, std::hash<U8>{}(bytes[i]));
        }
        return seed;
    }

} // namespace scn
