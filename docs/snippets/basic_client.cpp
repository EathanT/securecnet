#include <securecnet/scn.hpp>

int main() {
    scn::Client client{ scn::ClientConfig::low_latency() };
    client.on_connected([] {});
    client.on_text(1, [](std::string_view) {});

    auto options = scn::SendOptions{};
    options.channel = scn::Channel::ReliableOrdered;

    // Normally called after connect() reaches Established.
    (void)client.send_text(1, "hello", options);
    (void)client.send_reliable_text(2, "important");
    return 0;
}
