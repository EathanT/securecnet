#include "securecnet/scn.hpp"

#include <cstdio>
#include <string_view>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_api_ergonomics() {
    int fails = 0;

    fails += expect(version() == std::string_view("0.3.0"), "version helper should report package version");
    fails += expect(wire_protocol_version() == NetConfig::ProtocolVersion, "wire protocol helper should match NetConfig");
    fails += expect(errc_name(Errc::Backpressure) == std::string_view("Backpressure"), "Errc names should be stable");

    auto client_cfg = ClientConfig::builder()
        .send_budget_bytes_per_second(256 * 1024)
        .ordered_receive_window(128)
        .build();
    fails += expect(validate_client_config(client_cfg).ok(), "client builder should create valid config");

    auto server_cfg = ServerConfig::public_internet();
    fails += expect(validate_server_config(server_cfg).ok(), "public_internet server preset should be valid");

    IoContextConfig io_cfg{};
    io_cfg.max_posted_callbacks = 1;
    IoContext io{ io_cfg };
    auto rc = io.try_post([] {});
    fails += expect(rc.ok(), "first try_post should fit bounded queue");
    rc = io.try_post([] {});
    fails += expect(rc.code == Errc::QueueFull, "second try_post should hit bounded queue");
    (void)io.poll();

    Client client{ client_cfg };
    bool typed_called = false;
    client.on_text(7, [&](std::string_view) { typed_called = true; });
    client.on_connected([] {});
    client.on_disconnected([](CloseReason) {});

    AsyncClient async_client{ client_cfg };
    async_client.stop();

    return fails;
}
