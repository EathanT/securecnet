#include "securecnet/address.hpp"
#include "securecnet/bytebuf.hpp"
#include "securecnet/crypto.hpp"
#include "securecnet/packet.hpp"
#include "securecnet/protocol.hpp"
#include "securecnet/server.hpp"
#include "securecnet/udp_socket.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}



namespace {

struct ReceivedPacket {
    std::array<U8, NetConfig::MaxPacketBytes> buf{};
    PacketView view{};
};

struct ManualClient {
    UdpSocket sock{};
    Endpoint server{};
    KeyPair keypair{};
    SessionKeys keys{};
    std::array<U8, NetConfig::ClientNonceBytes> client_nonce{};
    RetryToken retry{};
    bool have_retry{ false };
    U64 conn_id{ 0 };
    U64 seq{ 1 };

    static Endpoint normalize_test_target(const Endpoint& ep) {
        Endpoint normalized = ep;
        auto* sa = reinterpret_cast<sockaddr*>(&normalized.addr);

        if (sa->sa_family == AF_INET) {
            auto* sin = reinterpret_cast<sockaddr_in*>(sa);
            if (sin->sin_addr.s_addr == htonl(INADDR_ANY)) {
                sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            }
        }
        else if (sa->sa_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(sa);
            if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
                sin6->sin6_addr = in6addr_loopback;
            }
        }

        return normalized;
    }

    Result open(const Endpoint& server_ep) {
        server = server_ep;
        auto family = reinterpret_cast<const sockaddr*>(&server.addr)->sa_family;
        auto rc = sock.open(family);
        if (!rc.ok()) return rc;
        rc = sock.set_nonblocking(true);
        if (!rc.ok()) return rc;
        rc = crypto_generate_keypair(keypair);
        if (!rc.ok()) return rc;
        crypto_random_bytes(client_nonce.data(), client_nonce.size());
        return Result::success();
    }

    ClientHello hello(bool with_token) const {
        ClientHello h{};
        h.client_public_key = keypair.public_key;
        h.client_nonce = client_nonce;
        h.has_retry_token = with_token && have_retry;
        if (h.has_retry_token) {
            h.retry_token = retry;
        }
        return h;
    }

    Result send_client_hello(bool with_token) {
        ClientHello h = hello(with_token);
        std::array<U8, 128> payload{};
        ByteWriter writer{ payload.data(), payload.size() };
        auto rc = write_client_hello(writer, h);
        if (!rc.ok()) return rc;

        PacketHeader header{};
        header.kind = static_cast<U8>(PacketKind::Handshake);
        header.conn_id = 0;
        header.seq = seq++;
        header.payload_len = static_cast<U32>(writer.off);

        std::array<U8, NetConfig::MaxPacketBytes> packet{};
        ST packet_len = 0;
        rc = pack_packet(header, payload.data(), writer.off, packet.data(), packet.size(), packet_len);
        if (!rc.ok()) return rc;
        return sock.send_to(server, packet.data(), packet_len);
    }

    Result build_transcript(const ServerHello& hello, U8* out, ST out_cap, ST& out_len) const {
        ClientHello ch = this->hello(true);
        ByteWriter writer{ out, out_cap };
        Result rc = writer.write_u16(NetConfig::ProtocolVersion);
        if (!rc.ok()) return rc;
        rc = writer.write_bytes(ch.client_public_key.data(), ch.client_public_key.size());
        if (!rc.ok()) return rc;
        rc = writer.write_bytes(ch.client_nonce.data(), ch.client_nonce.size());
        if (!rc.ok()) return rc;
        rc = writer.write_u8(ch.has_retry_token ? 1 : 0);
        if (!rc.ok()) return rc;
        if (ch.has_retry_token) {
            rc = write_retry_token(writer, ch.retry_token);
            if (!rc.ok()) return rc;
        }
        rc = writer.write_u8(ch.has_resumption_token ? 1 : 0);
        if (!rc.ok()) return rc;
        if (ch.has_resumption_token) {
            rc = write_resumption_token(writer, ch.resumption_token);
            if (!rc.ok()) return rc;
        }
        rc = writer.write_u64(hello.server_conn_id);
        if (!rc.ok()) return rc;
        rc = writer.write_bytes(hello.server_public_key.data(), hello.server_public_key.size());
        if (!rc.ok()) return rc;
        rc = writer.write_bytes(hello.server_nonce.data(), hello.server_nonce.size());
        if (!rc.ok()) return rc;
        rc = writer.write_u8(hello.has_resumption_token ? 1 : 0);
        if (!rc.ok()) return rc;
        if (hello.has_resumption_token) {
            rc = write_resumption_token(writer, hello.resumption_token);
            if (!rc.ok()) return rc;
        }
        out_len = writer.off;
        return Result::success();
    }

    Result derive_keys(const ServerHello& hello) {
        auto rc = crypto_derive_client_session_keys(keypair,
                                                    hello.server_public_key.data(), hello.server_public_key.size(),
                                                    keys);
        if (!rc.ok()) return rc;
        std::array<U8, 256> transcript{};
        ST transcript_len = 0;
        rc = build_transcript(hello, transcript.data(), transcript.size(), transcript_len);
        if (!rc.ok()) return rc;
        std::array<U8, NetConfig::TranscriptMacBytes> expected{};
        rc = crypto_keyed_hash(keys.rx.data(), keys.rx.size(), transcript.data(), transcript_len, expected.data(), expected.size());
        if (!rc.ok()) return rc;
        if (!crypto_constant_time_equal(expected.data(), hello.transcript_mac.data(), expected.size())) {
            return Result::fail(Errc::AuthFailed, "server hello MAC mismatch");
        }
        conn_id = hello.server_conn_id;
        return Result::success();
    }

    Result build_secure_packet(PacketKind kind, const U8* payload, ST payload_len,
                               const SessionKeys& use_keys, U64 use_seq,
                               std::array<U8, NetConfig::MaxPacketBytes>& out, ST& out_len) const {
        PacketHeader header{};
        header.kind = static_cast<U8>(kind);
        header.flags = PacketFlagEncrypted;
        header.conn_id = conn_id;
        header.seq = use_seq;
        header.payload_len = static_cast<U32>(payload_len + NetConfig::AeadTagBytes);

        std::array<U8, NetConfig::PacketHeaderBytes> aad{};
        ByteWriter aad_writer{ aad.data(), aad.size() };
        auto rc = write_packet_header(aad_writer, header);
        if (!rc.ok()) return rc;

        std::array<U8, NetConfig::AeadNonceBytes> nonce{};
        crypto_make_packet_nonce(conn_id, use_seq, nonce);

        std::array<U8, NetConfig::MaxPayloadBytes> ciphertext{};
        ST ciphertext_len = 0;
        rc = crypto_aead_encrypt(use_keys.tx.data(), use_keys.tx.size(),
                                 nonce.data(), nonce.size(),
                                 aad.data(), aad_writer.off,
                                 payload, payload_len,
                                 ciphertext.data(), ciphertext.size(), ciphertext_len);
        if (!rc.ok()) return rc;

        return pack_packet(header, ciphertext.data(), ciphertext_len, out.data(), out.size(), out_len);
    }

    Result send_secure_packet(PacketKind kind, const U8* payload, ST payload_len) {
        std::array<U8, NetConfig::MaxPacketBytes> packet{};
        ST packet_len = 0;
        auto rc = build_secure_packet(kind, payload, payload_len, keys, seq++, packet, packet_len);
        if (!rc.ok()) return rc;
        return sock.send_to(server, packet.data(), packet_len);
    }
};

static bool pump_server_and_receive(Server& srv, ManualClient& cli, ReceivedPacket& out, Endpoint& from, int timeout_ms) {
    ST n = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto src = srv.tick();
        if (!src.ok()) {
            return false;
        }
        auto rc = cli.sock.recv_from(from, out.buf.data(), out.buf.size(), n);
        if (rc.ok()) {
            rc = parse_packet(out.buf.data(), n, out.view);
            return rc.ok();
        }
        if (rc.code != Errc::WouldBlock) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

static bool establish_manual_client(Server& srv, ManualClient& cli) {
    if (!cli.send_client_hello(false).ok()) return false;
    ReceivedPacket packet{};
    Endpoint from{};
    if (!pump_server_and_receive(srv, cli, packet, from, 250)) return false;
    ByteReader retry_reader{ packet.view.payload, static_cast<ST>(packet.view.h.payload_len) };
    if (read_retry(retry_reader, cli.retry).code != Errc::Ok) return false;
    cli.have_retry = true;

    if (!cli.send_client_hello(true).ok()) return false;
    if (!pump_server_and_receive(srv, cli, packet, from, 250)) return false;
    ByteReader hello_reader{ packet.view.payload, static_cast<ST>(packet.view.h.payload_len) };
    ServerHello hello{};
    if (!read_server_hello(hello_reader, hello).ok()) return false;
    if (!cli.derive_keys(hello).ok()) return false;
    if (!cli.send_secure_packet(PacketKind::Keepalive, nullptr, 0).ok()) return false;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!srv.tick().ok()) return false;
        if (srv.stats().sessions_established >= 1) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return srv.stats().sessions_established >= 1;
}

} // namespace

int test_security() {
    int fails = 0;

    {
        Server srv;
        auto rc = srv.listen(0);
        fails += expect(rc.ok(), "expired-token: server listen failed");
        Endpoint server_local{};
        fails += expect(srv.local_endpoint(server_local).ok(), "expired-token: local_endpoint failed");

        ManualClient cli{};
        fails += expect(cli.open(server_local).ok(), "expired-token: open failed");
        fails += expect(cli.send_client_hello(false).ok(), "expired-token: initial hello send failed");

        ReceivedPacket packet{};
        Endpoint from{};
        fails += expect(pump_server_and_receive(srv, cli, packet, from, 250), "expired-token: retry not received");
        RetryToken retry{};
        ByteReader retry_reader{ packet.view.payload, static_cast<ST>(packet.view.h.payload_len) };
        fails += expect(read_retry(retry_reader, retry).ok(), "expired-token: retry parse failed");
        cli.retry = retry;
        cli.have_retry = true;

        std::this_thread::sleep_for(std::chrono::milliseconds(NetConfig::RetryTokenLifetimeMs + 50));
        fails += expect(cli.send_client_hello(true).ok(), "expired-token: retry hello send failed");
        fails += expect(pump_server_and_receive(srv, cli, packet, from, 500), "expired-token: close not received");
        ByteReader close_reader{ packet.view.payload, static_cast<ST>(packet.view.h.payload_len) };
        CloseFrame close_frame{};
        fails += expect(static_cast<PacketKind>(packet.view.h.kind) == PacketKind::Close, "expired-token: expected close packet");
        fails += expect(read_close_frame(close_reader, close_frame).ok(), "expired-token: close parse failed");
        fails += expect(close_frame.reason == CloseReason::CookieExpired, "expired-token: expected cookie expired close reason");
    }

    {
        Server srv;
        auto rc = srv.listen(0);
        fails += expect(rc.ok(), "malformed-handshake: server listen failed");
        Endpoint server_local{};
        fails += expect(srv.local_endpoint(server_local).ok(), "malformed-handshake: local_endpoint failed");

        UdpSocket sock{};
        fails += expect(sock.open(reinterpret_cast<const sockaddr*>(&server_local.addr)->sa_family).ok(), "malformed-handshake: socket open failed");
        std::array<U8, NetConfig::MaxPacketBytes> packet{};
        PacketHeader header{};
        header.kind = static_cast<U8>(PacketKind::Handshake);
        header.seq = 1;
        header.payload_len = 1;
        U8 one = static_cast<U8>(HandshakeType::ClientHello);
        ST packet_len = 0;
        fails += expect(pack_packet(header, &one, 1, packet.data(), packet.size(), packet_len).ok(), "malformed-handshake: pack failed");
        fails += expect(sock.send_to(server_local, packet.data(), packet_len).ok(), "malformed-handshake: send failed");
        fails += expect(srv.tick().ok(), "malformed-handshake: server tick failed");
        fails += expect(srv.stats().bad_packets >= 1, "malformed-handshake: server should count bad packet");
    }

    {
        Server srv;
        auto rc = srv.listen(0);
        fails += expect(rc.ok(), "replay/auth: server listen failed");
        Endpoint server_local{};
        fails += expect(srv.local_endpoint(server_local).ok(), "replay/auth: local_endpoint failed");

        ManualClient cli{};
        fails += expect(cli.open(server_local).ok(), "replay/auth: open failed");
        fails += expect(establish_manual_client(srv, cli), "replay/auth: handshake failed");

        U64 replay_seq = cli.seq;
        std::array<U8, NetConfig::MaxPacketBytes> replay_packet{};
        ST replay_len = 0;
        fails += expect(cli.build_secure_packet(PacketKind::Keepalive, nullptr, 0, cli.keys, replay_seq, replay_packet, replay_len).ok(), "replay/auth: build replay packet failed");
        fails += expect(cli.sock.send_to(server_local, replay_packet.data(), replay_len).ok(), "replay/auth: first replay send failed");
        fails += expect(srv.tick().ok(), "replay/auth: first replay tick failed");
        fails += expect(cli.sock.send_to(server_local, replay_packet.data(), replay_len).ok(), "replay/auth: duplicate replay send failed");
        fails += expect(srv.tick().ok(), "replay/auth: duplicate replay tick failed");
        fails += expect(srv.stats().replays_dropped >= 1, "replay/auth: duplicate packet should be dropped");
        cli.seq = replay_seq + 1;

        std::array<U8, NetConfig::MaxPacketBytes> bad_mac_packet{};
        ST bad_mac_len = 0;
        fails += expect(cli.build_secure_packet(PacketKind::Keepalive, nullptr, 0, cli.keys, cli.seq++, bad_mac_packet, bad_mac_len).ok(), "replay/auth: build bad-MAC packet failed");
        bad_mac_packet[bad_mac_len - 1] ^= 0x01;
        fails += expect(cli.sock.send_to(server_local, bad_mac_packet.data(), bad_mac_len).ok(), "replay/auth: bad-MAC send failed");
        fails += expect(srv.tick().ok(), "replay/auth: bad-MAC tick failed");
        fails += expect(srv.stats().auth_failures >= 1, "replay/auth: invalid MAC should be counted");
    }

    {
        Server srv;
        auto rc = srv.listen(0);
        fails += expect(rc.ok(), "wrong-key: server listen failed");
        Endpoint server_local{};
        fails += expect(srv.local_endpoint(server_local).ok(), "wrong-key: local_endpoint failed");

        ManualClient cli{};
        fails += expect(cli.open(server_local).ok(), "wrong-key: open failed");
        fails += expect(establish_manual_client(srv, cli), "wrong-key: handshake failed");

        SessionKeys wrong_keys{};
        crypto_random_bytes(wrong_keys.rx.data(), wrong_keys.rx.size());
        crypto_random_bytes(wrong_keys.tx.data(), wrong_keys.tx.size());

        std::array<U8, NetConfig::MaxPacketBytes> wrong_packet{};
        ST wrong_len = 0;
        fails += expect(cli.build_secure_packet(PacketKind::Keepalive, nullptr, 0, wrong_keys, cli.seq++, wrong_packet, wrong_len).ok(), "wrong-key: build packet failed");
        fails += expect(cli.sock.send_to(server_local, wrong_packet.data(), wrong_len).ok(), "wrong-key: send failed");
        fails += expect(srv.tick().ok(), "wrong-key: tick failed");
        fails += expect(srv.stats().auth_failures >= 1, "wrong-key: auth failure should be counted");
    }

    return fails;
}
