#include "securecnet/scn.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace scn;

namespace {

struct Pose {
    U32 tick{};
    I16 x{};
    I16 y{};
};

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

} // namespace

int test_router_request_reply() {
    int fails = 0;

    ClientRouter client_router;
    bool got_text = false;
    bool got_pose = false;
    bool got_fallback = false;
    bool got_error = false;

    client_router
        .on_text(1, [&](std::string_view text) {
            got_text = text == "hello";
        })
        .on_binary<Pose>(2, [&](const Pose& pose) -> Result {
            got_pose = pose.tick == 7 && pose.x == -4 && pose.y == 9;
            return Result::success();
        })
        .on(3, [&](const MsgView&) -> Result {
            return Result::fail(Errc::ProtocolError, "synthetic route failure");
        })
        .on_unhandled([&](const MsgView&) {
            got_fallback = true;
        })
        .on_error([&](const MsgView&, Result rc) {
            got_error = rc.code == Errc::ProtocolError;
        });

    const char hello[] = "hello";
    MsgView text_msg{ Channel::ReliableOrdered, 1, reinterpret_cast<const U8*>(hello), 5 };
    auto routed = client_router.dispatch(text_msg);
    fails += expect(routed.handled && routed.ok() && got_text, "ClientRouter should dispatch text handlers");

    Pose pose{ 7, -4, 9 };
    MsgView pose_msg{ Channel::SequencedUnreliable, 2, reinterpret_cast<const U8*>(&pose), static_cast<U16>(sizeof(pose)) };
    routed = client_router.dispatch(pose_msg);
    fails += expect(routed.handled && routed.ok() && got_pose, "ClientRouter should decode binary handlers");

    MsgView error_msg{ Channel::Reliable, 3, nullptr, 0 };
    routed = client_router.dispatch(error_msg);
    fails += expect(routed.handled && !routed.ok() && got_error, "ClientRouter should surface route errors");

    MsgView fallback_msg{ Channel::Unreliable, 99, nullptr, 0 };
    routed = client_router.dispatch(fallback_msg);
    fails += expect(routed.handled && routed.ok() && got_fallback, "ClientRouter should dispatch fallback handlers");

    ServerRouter server_router;
    bool server_got_text = false;
    server_router.on_text(4, [&](Server::Peer peer, std::string_view text) {
        server_got_text = !peer.is_valid() && text == "world";
    });
    const char world[] = "world";
    MsgView server_msg{ Channel::ReliableOrdered, 4, reinterpret_cast<const U8*>(world), 5 };
    routed = server_router.dispatch(Server::Peer{}, server_msg);
    fails += expect(routed.handled && routed.ok() && server_got_text, "ServerRouter should dispatch text handlers with peer");

    const std::array<U8, 3> payload{ 1, 2, 3 };
    auto frame = make_request_reply_frame(RequestReplyKind::Request, 42, 9, payload);
    fails += expect(frame.ok(), "request frame should encode");
    if (frame.ok()) {
        RequestReplyFrame parsed{};
        auto rc = read_request_reply_frame(std::span<const U8>(frame.value.data(), frame.value.size()), parsed);
        fails += expect(rc.ok(), "request frame should parse");
        fails += expect(parsed.kind == RequestReplyKind::Request && parsed.request_id == 42 && parsed.type == 9,
                        "request frame metadata should round-trip");
        fails += expect(parsed.len == payload.size() && std::memcmp(parsed.data, payload.data(), payload.size()) == 0,
                        "request frame payload should round-trip");
    }

    auto bad = make_request_reply_frame(RequestReplyKind::Request, 0, 9, payload);
    fails += expect(!bad.ok() && bad.code == Errc::InvalidArg, "request id zero should be rejected");

    ClientRequestTable requests;
    auto response_frame = make_request_reply_frame(RequestReplyKind::Response, 777, 9, payload);
    fails += expect(response_frame.ok(), "response frame should encode");
    if (response_frame.ok()) {
        MsgView response_msg{ Channel::ReliableOrdered,
                              RequestReplyDefaultMessageType,
                              response_frame.value.data(),
                              static_cast<U16>(response_frame.value.size()) };
        routed = requests.dispatch(response_msg);
        fails += expect(routed.handled && !routed.ok() && routed.rc.code == Errc::ProtocolError,
                        "unknown response ids should be handled as protocol errors");
    }

    Client client;
    auto future_result = requests.request(client, 9, payload, 50);
    fails += expect(!future_result.ok() && requests.pending_count() == 0,
                    "request table should remove pending request when send fails");

    return fails;
}
