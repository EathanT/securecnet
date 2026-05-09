#include <securecnet/scn.hpp>

int main() {
    scn::AsyncClient client{ scn::ClientConfig::reliable_gameplay() };
    client.client().on_text(1, [](std::string_view) {});
    auto future = client.send_ordered_text(1, "hello");
    client.stop();
    return 0;
}
