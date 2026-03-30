#include <cstdio>
#include <cstdlib>

<<<<<<< HEAD

=======
>>>>>>> origin/main
int test_bytebuf();
int test_message();
int test_address();
int test_packet();
<<<<<<< HEAD
int test_udp();
int test_client_server();
=======
>>>>>>> origin/main

int main() {
    int fails = 0;

    auto run = [&](const char* name, int(*fn)()) {
        const int rc = fn();
<<<<<<< HEAD
        if (rc != 0) {
=======
        if (rc != 0) { 
>>>>>>> origin/main
            std::printf("[ FAIL ] %s\n", name);
            fails++;
        }
        else {
            std::printf("[ OK ] %s\n", name);
        }
<<<<<<< HEAD
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
=======

    };


    run("bytebuf", test_bytebuf);
    run("message", test_message);
    run("address", test_address);
	run("packet", test_packet);

    std::printf("\nTotal fails: %d\n", fails);
    return fails ? 1 : 0;
}
>>>>>>> origin/main
