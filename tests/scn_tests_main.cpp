#include <cstdio>
#include <cstdlib>

int test_bytebuf();
int test_message();
int test_address();
int test_packet();
int test_udp();
int test_client_server();

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
    run("client_server", test_client_server);

    std::printf("\nTotal fails: %d\n", fails);
    return fails ? 1 : 0;
}
