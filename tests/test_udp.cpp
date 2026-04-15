#include "securecnet/socket_init.hpp"
#include "securecnet/address.hpp"
#include "securecnet/udp_socket.hpp"
#include "securecnet/packet.hpp"

#include "securecnet/message.hpp"
#include <chrono>
#include <thread>
#include <cstdio>
#include <cstring>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) { std::printf("  %s\n", msg); return 1; }
    return 0;
}


int test_udp() {
    int fails = 0;

    SocketInit init;
    if (!init.status().ok()) return 1;

    // resolve server bind endpoint: 127.0.0.1:0
    std::vector<Endpoint> eps;
    auto rc = resolve_endpoints("127.0.0.1", "0", false, eps);
    if (!rc.ok() || eps.empty()) return 1;

    Endpoint bind_ep = eps[0];

    // server socket
    UdpSocket server;
    rc = server.open(((sockaddr*)&bind_ep.addr)->sa_family);
    if (!rc.ok()) return 1;

    rc = server.bind(bind_ep);
    if (!rc.ok()) return 1;

    Endpoint server_local{};
    rc = server.local_endpoint(server_local);
    if (!rc.ok()) return 1;

    // nonblocking server so test cannot hang forever
    rc = server.set_nonblocking(true);
    if (!rc.ok()) return 1;

    // client socket
    UdpSocket client;
    rc = client.open(((sockaddr*)&server_local.addr)->sa_family);
    if (!rc.ok()) return 1;

    // build packet payload (with framed message inside)
    U8 payload[256]{};
    ByteWriter pw{ payload, sizeof(payload) };

    const char msgbytes[] = "hello";
    rc = write_message(pw, Channel::Unreliable, 42, msgbytes, (U16)5);
    if (!rc.ok()) return 1;

    PacketHeader h{};
    h.flags = 0;
    h.conn_id = 1;
    h.seq = 1;

    U8 pkt[NetConfig::MaxPacketBytes]{};
    ST pkt_len = 0;
    rc = pack_packet(h, payload, pw.off, pkt, sizeof(pkt), pkt_len);
    if (!rc.ok()) return 1;

    // send
    rc = client.send_to(server_local, pkt, pkt_len);
    if (!rc.ok()) return 1;

    // recv with timeout loop
    U8 rbuf[NetConfig::MaxPacketBytes]{};
    ST rlen = 0;
    Endpoint from{};

    auto start = std::chrono::steady_clock::now();
    bool got = false;

    while (!got) {
        rc = server.recv_from(from, rbuf, sizeof(rbuf), rlen);
        if (rc.ok()) {
            got = true;
            break;
        }
        if (rc.code != Errc::WouldBlock) return 1;

        auto now = std::chrono::steady_clock::now();
        if (now - start > std::chrono::milliseconds(500)) {
            std::printf("  timed out waiting for packet\n");
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }



    // recv_from should report truncated datagrams when the caller buffer is too small
    {
        U8 small_payload[32]{};
        for (int i = 0; i < 32; ++i) {
            small_payload[i] = static_cast<U8>(i);
        }

        auto send_rc = client.send_to(server_local, small_payload, sizeof(small_payload));
        fails += expect(send_rc.ok(), "truncate send failed");

        U8 tiny_buf[8]{};
        ST tiny_len = 0;
        Endpoint tiny_from{};
        auto truncate_start = std::chrono::steady_clock::now();
        bool got_truncated = false;

        while (!got_truncated) {
            auto recv_rc = server.recv_from(tiny_from, tiny_buf, sizeof(tiny_buf), tiny_len);
            if (recv_rc.code == Errc::Truncated) {
                got_truncated = true;
                break;
            }
            if (recv_rc.ok()) {
                std::printf("  expected truncated datagram but recv succeeded\n");
                ++fails;
                break;
            }
            if (recv_rc.code != Errc::WouldBlock) {
                std::printf("  unexpected recv status while waiting for truncation\n");
                ++fails;
                break;
            }

            auto now = std::chrono::steady_clock::now();
            if (now - truncate_start > std::chrono::milliseconds(500)) {
                std::printf("  timed out waiting for truncated packet\n");
                ++fails;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        fails += expect(got_truncated, "recv_from should report truncated datagram");
    }

    // parse packet
    PacketView pv{};
    rc = parse_packet(rbuf, rlen, pv);
    fails += expect(rc.ok(), "parse_packet failed");

    // parse framed message inside payload
    ByteReader pr{ pv.payload, (ST)pv.h.payload_len };
    MsgView mv{};
    rc = read_message(pr, mv);
    fails += expect(rc.ok(), "read_message failed");
    fails += expect(mv.type == 42, "msg type mismatch");
    fails += expect(mv.len == 5, "msg len mismatch");
    fails += expect(std::memcmp(mv.data, "hello", 5) == 0, "msg payload mismatch");

    return fails;
}