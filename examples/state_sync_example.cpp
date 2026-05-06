#include "example_common.hpp"

#include <string>

using namespace scn;

namespace {
constexpr U8 kSubscribeType = 21;
constexpr U8 kStateType = 22;

struct StateSnapshot {
    U32 tick{ 0 };
    U32 x_mm{ 0 };
    U32 y_mm{ 0 };
    U32 vx_mm_per_tick{ 0 };
    U32 vy_mm_per_tick{ 0 };
};

Result encode_state(ByteWriter& w, const StateSnapshot& snapshot) {
    auto rc = w.write_u32(snapshot.tick);
    if (!rc.ok()) return rc;
    rc = w.write_u32(snapshot.x_mm);
    if (!rc.ok()) return rc;
    rc = w.write_u32(snapshot.y_mm);
    if (!rc.ok()) return rc;
    rc = w.write_u32(snapshot.vx_mm_per_tick);
    if (!rc.ok()) return rc;
    return w.write_u32(snapshot.vy_mm_per_tick);
}

Result decode_state(ByteReader& r, StateSnapshot& snapshot) {
    snapshot = {};
    auto rc = r.read_u32(snapshot.tick);
    if (!rc.ok()) return rc;
    rc = r.read_u32(snapshot.x_mm);
    if (!rc.ok()) return rc;
    rc = r.read_u32(snapshot.y_mm);
    if (!rc.ok()) return rc;
    rc = r.read_u32(snapshot.vx_mm_per_tick);
    if (!rc.ok()) return rc;
    rc = r.read_u32(snapshot.vy_mm_per_tick);
    if (!rc.ok()) return rc;
    return (r.remaining() == 0) ? Result::success() : Result::fail(Errc::BadPacket, "extra bytes in state snapshot");
}
}

static void usage() {
    std::printf(
        "Usage:\n"
        "  state_sync_example --server <port>\n"
        "  state_sync_example --client <host> <port>\n");
}

static int run_server(const char* port) {
    Server srv;
    auto rc = srv.listen(port);
    if (!rc.ok()) {
        return scn_examples::print_result("server.listen", rc);
    }
    Endpoint local{};
    rc = srv.local_endpoint(local);
    if (!rc.ok()) {
        return scn_examples::print_result("server.local_endpoint", rc);
    }
    std::printf("state sync server listening on %s\n", local.to_string().c_str());

    Server::Peer subscriber{};
    bool have_subscriber = false;
    auto next_send = std::chrono::steady_clock::now();
    StateSnapshot snapshot{};
    snapshot.vx_mm_per_tick = 125;
    snapshot.vy_mm_per_tick = 40;

    srv.on_message([&](Server::Peer peer, const MsgView& msg) {
        if (msg.type == kSubscribeType) {
            subscriber = peer;
            have_subscriber = true;
            std::printf("[server] client subscribed: conn=%llu\n",
                        static_cast<unsigned long long>(peer.conn_id()));
        }
    });

    while (true) {
        rc = srv.tick();
        if (!rc.ok()) {
            return scn_examples::print_result("server.tick", rc);
        }

        const auto now = std::chrono::steady_clock::now();
        if (have_subscriber && now >= next_send) {
            snapshot.tick += 1;
            snapshot.x_mm += snapshot.vx_mm_per_tick;
            snapshot.y_mm += snapshot.vy_mm_per_tick;

            std::array<U8, 32> payload{};
            ByteWriter writer{ payload.data(), payload.size() };
            auto encode_rc = encode_state(writer, snapshot);
            if (!encode_rc.ok()) {
                return scn_examples::print_result("encode_state", encode_rc);
            }

            SendOptions options{};
            options.channel = Channel::SequencedUnreliable;
            auto send_rc = subscriber.send(options, kStateType,
                                           std::span<const U8>(payload.data(), writer.off));
            if (!send_rc.ok()) {
                if (send_rc.code == Errc::Closed || send_rc.code == Errc::StateError) {
                    std::printf("[server] subscriber disconnected: conn=%llu\n",
                                static_cast<unsigned long long>(subscriber.conn_id()));
                    subscriber = Server::Peer{};
                    have_subscriber = false;
                } else {
                    std::printf("state send failed: err=%u msg=%.*s\n",
                                static_cast<unsigned>(send_rc.code),
                                static_cast<int>(send_rc.msg.size()),
                                send_rc.msg.data() ? send_rc.msg.data() : "");
                }
            }
            next_send = now + std::chrono::milliseconds(100);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static int run_client(const char* host, const char* port) {
    Client cli;
    auto rc = cli.connect(host, port);
    if (!rc.ok()) {
        return scn_examples::print_result("client.connect", rc);
    }

    bool subscribed = false;
    int updates = 0;

    cli.on_message([&](const MsgView& msg) {
        if (msg.type != kStateType) {
            return;
        }
        ByteReader reader{ msg.data, msg.len };
        StateSnapshot snapshot{};
        auto decode_rc = decode_state(reader, snapshot);
        if (!decode_rc.ok()) {
            std::printf("decode_state failed: err=%u msg=%.*s\n",
                        static_cast<unsigned>(decode_rc.code),
                        static_cast<int>(decode_rc.msg.size()),
                        decode_rc.msg.data());
            return;
        }
        ++updates;
        std::printf("tick=%u position=(%u,%u) velocity=(%u,%u)\n",
                    static_cast<unsigned>(snapshot.tick),
                    static_cast<unsigned>(snapshot.x_mm),
                    static_cast<unsigned>(snapshot.y_mm),
                    static_cast<unsigned>(snapshot.vx_mm_per_tick),
                    static_cast<unsigned>(snapshot.vy_mm_per_tick));
    });

    const bool completed = scn_examples::pump_until(cli, 3000, [&] {
        if (!subscribed && cli.state() == ConnectionState::Established) {
            SendOptions options{};
            options.channel = Channel::Reliable;
            auto send_rc = cli.send(options, kSubscribeType, std::span<const U8>{});
            if (!send_rc.ok()) {
                std::printf("subscribe failed: err=%u msg=%.*s\n",
                            static_cast<unsigned>(send_rc.code),
                            static_cast<int>(send_rc.msg.size()),
                            send_rc.msg.data());
                return true;
            }
            subscribed = true;
        }
        return updates >= 20 || cli.state() == ConnectionState::Closed;
    });

    if (!completed || updates < 20) {
        std::printf("state sync client did not receive enough updates\n");
        return 1;
    }

    (void)cli.close(CloseReason::Normal);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        usage();
        return 1;
    }
    const std::string mode = argv[1];
    if (mode == "--server" && argc == 3) {
        return run_server(argv[2]);
    }
    if (mode == "--client" && argc == 4) {
        return run_client(argv[2], argv[3]);
    }
    usage();
    return 1;
}
