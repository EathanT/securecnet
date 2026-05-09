#include <securecnet/scn.hpp>

int main() {
    scn::Server server{ scn::ServerConfig::public_internet() };
    server.on_peer_connected([](scn::Server::Peer) {});
    server.on_text(1, [](scn::Server::Peer peer, std::string_view text) {
        (void)peer.send_ordered_text(1, text);
    });
    return 0;
}
