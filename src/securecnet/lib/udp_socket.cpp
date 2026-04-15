#include "securecnet/udp_socket.hpp"

#include <cerrno>
#include <cstring>
#include <limits>

namespace scn {

    static int last_sock_err() {
#ifdef _WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    static bool is_would_block(int e) {
#ifdef _WIN32
        return e == WSAEWOULDBLOCK;
#else
        return e == EWOULDBLOCK || e == EAGAIN;
#endif
    }

    static void close_sock(socket_t s) {
#ifdef _WIN32
        closesocket(s);
#else
        ::close(s);
#endif
    }

    static Result check_socket_len(ST len) {
        if (len > static_cast<ST>(std::numeric_limits<int>::max())) {
            return Result::fail(Errc::InvalidArg, "buffer too large for socket call");
        }
        return Result::success();
    }

    static Result send_datagram_common(socket_t s,const U8* data, ST len,
                                       const sockaddr* to, socklen_t to_len,
                                       bool connected) {
        if (s == kInvalidSocket) {
            return Result::fail(Errc::InvalidArg, "socket not open");
        }
        if (!data && len > 0) {
            return Result::fail(Errc::InvalidArg, "data is null");
        }

        auto rc = check_socket_len(len);
        if (!rc.ok()) {
            return rc;
        }

#ifdef _WIN32
        int sent = connected
            ? ::send(s, reinterpret_cast<const char*>(data), static_cast<int>(len), 0)
            : ::sendto(s, reinterpret_cast<const char*>(data), static_cast<int>(len), 0, to, to_len);
#else
        ssize_t sent = connected
            ? ::send(s, reinterpret_cast<const char*>(data), len, 0)
            : ::sendto(s, reinterpret_cast<const char*>(data), len, 0, to, to_len);
#endif

        
        if (sent < 0) {
            const int e = last_sock_err();
            if (is_would_block(e))
                return Result::fail(Errc::WouldBlock, connected ? "send would block" : "sendto would block");

            return Result::fail(Errc::SocketError, connected ? "send() failed" : "sendto() failed");
        }

        if (static_cast<ST>(sent) != len)
            return Result::fail(Errc::SocketError, "partial UDP send (unexpected)");

        return Result::success();
    }

    static Result recv_datagram_common(socket_t s, U8* out, ST out_cap, ST& out_len, Endpoint* from) {
        out_len = 0;

        if (s == kInvalidSocket)
            return Result::fail(Errc::InvalidArg, "socket not open");

        if (!out && out_cap > 0)
            return Result::fail(Errc::InvalidArg, "out is null");

    
        auto rc = check_socket_len(out_cap);
        if (!rc.ok()) {
            return rc;
        }

        sockaddr_storage ss{};
        socklen_t slen = static_cast<socklen_t>(sizeof(ss));

#ifdef __linux__
        const int flags = MSG_TRUNC;
#else
        const int flags = 0;
#endif

#ifdef _WIN32
        int n = from
            ? ::recvfrom(s, reinterpret_cast<char*>(out), static_cast<int>(out_cap), flags, reinterpret_cast<sockaddr*>(&ss), &slen)
            : ::recv(s, reinterpret_cast<char*>(out), static_cast<int>(out_cap), flags);
#else
        ssize_t n = from
            ? ::recvfrom(s, reinterpret_cast<char*>(out), out_cap, flags, reinterpret_cast<sockaddr*>(&ss), &slen)
            : ::recv(s, reinterpret_cast<char*>(out), out_cap, flags);
#endif

        if (n < 0) {
            const int e = last_sock_err();
            if (is_would_block(e))
                return Result::fail(Errc::WouldBlock, from ? "recvfrom would block" : "recv would block");
#ifdef _WIN32
            if (e == WSAEMSGSIZE) {
                return Result::fail(Errc::Truncated, "udp datagram truncated)");
            }
#endif
            return Result::fail(Errc::SocketError, from ? "recvfrom() failed" : "recv() failed");
        }

#ifdef _WIN32
        if (static_cast<ST>(n) > out_cap) {
            return Result::fail(Errc::Truncated, "udp datagram truncated");
        }
#else
        if (n > static_cast<ssize_t>(out_cap)) {
            return Result::fail(Errc::Truncated, "udp datagram truncated");
        }
#endif

        if (from) {
            from->addr = ss;
            from->len  = slen; 
        }

        out_len = static_cast<ST>(n);
        return Result::success();
    }

    UdpSocket::~UdpSocket() {
        close(); 
    }

    bool UdpSocket::is_open() const {
        return _s != kInvalidSocket; 
    }

    Result UdpSocket::open(int family) {
        if (is_open()) 
            return Result::success();

        _s = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
        if (_s == kInvalidSocket)
            return Result::fail(Errc::SocketError, "socket() failed");

        return Result::success();
    }

    void UdpSocket::close() {
        if (!is_open()) return;
        close_sock(_s);
        _s = kInvalidSocket;
    }

    Result UdpSocket::bind(const Endpoint& local) {
        if (!is_open()) {
            auto rc = open(reinterpret_cast<const sockaddr*>(&local.addr)->sa_family);
            if (!rc.ok())
                return rc;
        }

        const int rc = ::bind(_s, reinterpret_cast<const sockaddr*>(&local.addr), local.len);
        if (rc != 0)
            return Result::fail(Errc::SocketError, "bind() failed");

        return Result::success();
    }

    Result UdpSocket::connect(const Endpoint& remote) {
        if (!is_open()) {
            auto rc = open(reinterpret_cast<const sockaddr*>(&remote.addr)->sa_family);
            if (!rc.ok())
                return rc;
        }

        const int rc = ::connect(_s, reinterpret_cast<const sockaddr*>(&remote.addr), remote.len);
        if (rc != 0)
            return Result::fail(Errc::SocketError, "connect() failed");

        return Result::success(); 
    }

    Result UdpSocket::set_nonblocking(bool on) {
        if (!is_open()) return Result::fail(Errc::InvalidArg, "socket not open");

#ifdef _WIN32
        u_long mode = on ? 1UL : 0UL;
        const int rc = ioctlsocket(_s, FIONBIO, &mode);
        if (rc != 0)
            return Result::fail(Errc::SocketError, "ioctlsocket(FIONBIO) failed");
#else
        const int flags = fcntl(_s, F_GETFL, 0);
        if (flags < 0) 
            return Result::fail(Errc::SocketError, "fcntl(F_GETFL) failed");

        const int rc = fcntl(_s, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
        if (rc != 0) 
            return Result::fail(Errc::SocketError, "fcntl(F_SETFL) failed");
#endif
        return Result::success();
    }

    Result UdpSocket::send_to(const Endpoint& to, const U8* data, ST len) {
        return send_datagram_common(_s, data, len, reinterpret_cast<const sockaddr*>(&to.addr), to.len, false);
    }

    Result UdpSocket::send(const U8* data, ST len) {
        return send_datagram_common(_s, data, len, nullptr, 0, true);
    }

    Result UdpSocket::recv_from(Endpoint& from, U8* out, ST out_cap, ST& out_len) {
        return recv_datagram_common(_s, out, out_cap, out_len, &from);
    }

    Result UdpSocket::recv(U8* out, ST out_cap, ST& out_len) {
        return recv_datagram_common(_s, out, out_cap, out_len, nullptr);
    }

    Result UdpSocket::local_endpoint(Endpoint& out) const {
        if (!is_open())
            return Result::fail(Errc::InvalidArg, "socket not open");

        sockaddr_storage ss{};
        socklen_t slen = static_cast<socklen_t>(sizeof(ss));
        const int rc = getsockname(_s, reinterpret_cast<sockaddr*>(&ss), &slen);  
        if (rc != 0)
            return Result::fail(Errc::SocketError, "getsockname() failed");

        out.addr = ss;
        out.len = slen;
        return Result::success();
    }

}