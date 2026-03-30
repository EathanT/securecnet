#pragma once
#include "securecnet/result.hpp"
#include "securecnet/endpoint.hpp"
#include "securecnet/platform.hpp"
#include <cstddef>
#include <cstdint>

<<<<<<< HEAD

=======
>>>>>>> origin/main
namespace scn {

    class UdpSocket {
    public:
        UdpSocket() = default;
        ~UdpSocket();

<<<<<<< HEAD
        Result open(int family);
        Result bind(const Endpoint& local);
        Result connect(const Endpoint& remote);
        Result set_nonblocking(bool on);

        Result send_to(const Endpoint& to, const U8* data, ST len);
        Result send(const U8* data, ST len);
        Result recv_from(Endpoint& from, U8* out, ST out_cap, ST& out_len);
        Result recv(U8* out, ST out_cap, ST& out_len);

        Result local_endpoint(Endpoint& out) const; 

        void close();
        bool is_open() const;
=======
        Result open();
        Result bind(const Endpoint& local);
        Result set_nonblocking(bool on);

        Result send_to(const Endpoint& to, const U8* data, ST len);
        Result recv_from(Endpoint& from, U8* out, ST out_cap, ST& out_len);

        void close();
>>>>>>> origin/main

    private:
        socket_t _s{ kInvalidSocket };
    };

}