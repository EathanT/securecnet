#include <securecnet/scn.hpp>

#include <array>

int main() {
    scn::Client client;
    scn::ClientRouter routes;
    scn::ClientRequestTable requests;

    routes.on_text(1, [](std::string_view text) {
        (void)text;
    });
    routes.on(scn::RequestReplyDefaultMessageType, [&](const scn::MsgView& msg) -> scn::Result {
        return requests.dispatch(msg).rc;
    });
    routes.attach(client);

    std::array<scn::U8, 4> payload{ 1, 2, 3, 4 };
    auto frame = scn::make_request_reply_frame(scn::RequestReplyKind::Request, 1, 42, payload);
    return frame.ok() ? 0 : 1;
}
