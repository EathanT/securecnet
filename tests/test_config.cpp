#include "securecnet/config.hpp"

#include <cstdio>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_config() {
    int fails = 0;

    {
        ClientConfig cfg{};
        fails += expect(validate_client_config(cfg).ok(), "default client config should validate");

        ServerConfig server_cfg{};
        fails += expect(validate_server_config(server_cfg).ok(), "default server config should validate");
    }

    {
        ClientConfig cfg{};
        cfg.keepalive_interval_ms = cfg.idle_timeout_ms;
        auto rc = validate_client_config(cfg);
        fails += expect(!rc.ok(), "client config should reject keepalive >= idle timeout");
    }

    {
        FragmentationConfig cfg{};
        cfg.max_fragments_per_message = 1;
        cfg.max_reassembled_message_bytes = static_cast<U32>(NetConfig::MaxFragmentDataBytes + 1);
        auto rc = validate_fragmentation_config(cfg);
        fails += expect(!rc.ok(), "fragmentation config should reject too-small fragment count budget");
    }

    {
        FragmentationConfig cfg{};
        cfg.max_total_reassembly_memory_per_peer = cfg.max_reassembled_message_bytes - 1;
        auto rc = validate_fragmentation_config(cfg);
        fails += expect(!rc.ok(), "fragmentation config should reject per-peer memory smaller than one message");
    }

    {
        ServerConfig cfg{};
        cfg.max_peer_sessions = 0;
        auto rc = validate_server_config(cfg);
        fails += expect(!rc.ok(), "server config should reject zero max_peer_sessions");
    }

    {
        ServerConfig cfg{};
        cfg.abuse.max_queued_reliable_bytes_per_peer = cfg.reliability.max_pending_bytes / 8;
        auto rc = validate_server_config(cfg);
        fails += expect(!rc.ok(), "server config should reject too-small queued reliable byte budget");
    }

    return fails;
}
