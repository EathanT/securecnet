#include "securecnet/scn.hpp"

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>

using namespace scn;

namespace {

struct WireInput {
    std::uint32_t buttons{};
    std::int16_t aim_x{};
    std::int16_t aim_y{};
};

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

} // namespace

int test_app_helpers() {
    int fails = 0;

    static_assert(fits_latest<WireInput>());
    static_assert(fits_reliable<WireInput>());

    WireInput input{};
    input.buttons = 3;
    input.aim_x = -4;
    input.aim_y = 9;

    auto input_bytes = bytes_of(input);
    fails += expect(input_bytes.size() == sizeof(WireInput), "bytes_of should expose object bytes");

    MsgView msg{};
    msg.channel = Channel::SequencedUnreliable;
    msg.type = 42;
    msg.data = input_bytes.data();
    msg.len = static_cast<U16>(input_bytes.size());
    fails += expect(msg.u8span().size() == sizeof(WireInput), "MsgView::u8span should expose bytes");
    fails += expect(msg.byte_span().size() == sizeof(WireInput), "MsgView::byte_span should expose std::byte view");

    auto decoded = msg.as<WireInput>();
    fails += expect(decoded.ok(), "MsgView::as should decode exact-size POD messages");
    if (decoded.ok()) {
        fails += expect(decoded.value.buttons == input.buttons, "decoded buttons should match");
        fails += expect(decoded.value.aim_x == input.aim_x, "decoded aim_x should match");
        fails += expect(decoded.value.aim_y == input.aim_y, "decoded aim_y should match");
    }

    std::array<U8, 64> buf{};
    BinaryWriter writer{ std::span<U8>(buf.data(), buf.size()) };
    auto rc = writer.u16(0x1234);
    if (rc.ok()) rc = writer.i16(-5);
    if (rc.ok()) rc = writer.pod(input);
    fails += expect(rc.ok(), "BinaryWriter should encode primitives and POD values");

    BinaryReader reader{ std::span<const U8>(buf.data(), writer.size()) };
    U16 a{};
    I16 b{};
    rc = reader.u16(a);
    if (rc.ok()) rc = reader.i16(b);
    auto decoded_pod = reader.pod<WireInput>();
    fails += expect(rc.ok() && decoded_pod.ok(), "BinaryReader should decode primitives and POD values");
    fails += expect(a == 0x1234 && b == -5, "BinaryReader should use network byte order for integers");
    if (decoded_pod.ok()) {
        fails += expect(std::memcmp(&decoded_pod.value, &input, sizeof(input)) == 0, "BinaryReader POD should round-trip");
    }

    Client client{};
    client.on_binary<WireInput>(42, [](const WireInput&) {});
    client.on_backpressure([](const BackpressureInfo&) {});
    rc = client.send_latest(42, input);
    fails += expect(rc.code == Errc::StateError, "typed client sends should route through normal send state checks");

    Server server{};
    server.on_binary<WireInput>(42, [](Server::Peer, const WireInput&) {});
    server.on_peer_ready([](Server::Peer) {});
    server.on_backpressure([](Server::Peer, const BackpressureInfo&) {});
    server.for_each_peer([](Server::Peer) {});
    rc = server.broadcast_latest(42, input);
    fails += expect(rc.ok(), "broadcast with no peers should be a no-op success");

    LocalSession local{};
    (void)local.client();
    (void)local.server();

    return fails;
}
