#include "securecnet/address.hpp"
#include "securecnet/socket_init.hpp"

#include <cstdio>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    
    return 0;
}

static void print_result(const scn::Result& r) {
    std::printf("  err=%u msg=%.*s\n",
        static_cast<unsigned>(r.code),
        static_cast<int>(r.msg.size()),
        r.msg.data() ? r.msg.data() : "");
}

int test_address() {

    SocketInit init;
    if (!init.status().ok()) {
        print_result(init.status());
        return 1;
    }

    std::vector<Endpoint> eps;
    auto rc = resolve_endpoints("127.0.0.1", "27015", false, eps);
    if (!rc.ok()) {
        print_result(rc);
        return 1;
    }

    int fails = 0;
    fails += expect(!eps.empty(), "resolve returned zero endpoints");
    return fails;
}