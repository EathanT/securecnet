#include <cstdio>
#include <cstdlib>

int test_bytebuf();
int test_message();
int test_address();
int test_packet();
int test_udp();
int test_protocol();
int test_reliability_ext();
int test_mtu();
int test_abuse();
int test_soak();
int test_nat_stream();
int test_config();
int test_fragmentation();
int test_channels();
int test_client_server();
int test_fragment_transport();
int test_reliability();
int test_security();
int test_resumption();
int test_fuzz();
int test_validation_hardening();
int test_async();
int test_api_ergonomics();
int test_app_helpers();
int test_router_request_reply();

int main() {
    int fails = 0;

    auto run = [&](const char* name, int(*fn)()) {
        const int rc = fn();
        if (rc != 0) {
            std::printf("[ FAIL ] %s\n", name);
            fails++;
        }
        else {
            std::printf("[ OK ] %s\n", name);
        }
    };

    run("bytebuf", test_bytebuf);
    run("message", test_message);
    run("address", test_address);
    run("packet", test_packet);
    run("udp", test_udp);
    run("protocol", test_protocol);
    run("reliability_ext", test_reliability_ext);
    run("mtu", test_mtu);
    run("abuse", test_abuse);
    run("soak", test_soak);
    run("nat_stream", test_nat_stream);
    run("config", test_config);
    run("fragmentation", test_fragmentation);
    run("channels", test_channels);
    run("reliability", test_reliability);
    run("client_server", test_client_server);
    run("fragment_transport", test_fragment_transport);
    run("security", test_security);
    run("resumption", test_resumption);
    run("fuzz", test_fuzz);
    run("validation_hardening", test_validation_hardening);
    run("async", test_async);
    run("api_ergonomics", test_api_ergonomics);
    run("app_helpers", test_app_helpers);
    run("router_request_reply", test_router_request_reply);

    std::printf("\nTotal fails: %d\n", fails);
    return fails ? 1 : 0;
}
