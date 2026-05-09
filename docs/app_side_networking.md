# Application-side networking helpers

This layer keeps securecnet message-oriented and transport-focused while removing repetitive glue from games, demos, and small applications.

## Typed binary messages

Use trivially-copyable wire structs when you want compact binary messages without writing manual `memcpy` dispatch every time.

```cpp
struct PlayerInput {
  std::uint32_t buttons{};
  std::int16_t aim_x{};
  std::int16_t aim_y{};
};

client.on_binary<PlayerInput>(1, [](const PlayerInput& input) {
  // size-checked and copied before this callback runs
});

client.send_latest(1, PlayerInput{});
```

The same pattern works on the server:

```cpp
server.on_binary<PlayerInput>(1, [](scn::Server::Peer peer, const PlayerInput& input) {
  peer.send_reliable(2, input);
});
```

## Message views

`MsgView` now exposes byte-safe views:

```cpp
std::span<const scn::U8> raw = msg.u8span();
std::span<const std::byte> bytes = msg.byte_span();
auto decoded = msg.as<PlayerInput>();
```

## Broadcast and peer iteration

Server applications can now iterate and broadcast without maintaining a duplicate peer list.

```cpp
server.for_each_peer([](scn::Server::Peer peer) {
  // established peers only
});

server.broadcast_latest(3, WorldSnapshot{});
server.broadcast_except(sender, scn::SendOptions{scn::Channel::Reliable, scn::SendPriority::Normal, 0}, 4, payload);
```

## Peer context

Each peer has a stable application-facing `peer_id()` separate from the transport connection ID. You can also attach one opaque pointer when that is enough for application context.

```cpp
peer.peer_id();
peer.set_user_data(player_ptr);
auto* player = peer.user_data<Player>();
```

## Backpressure notifications

Callbacks report application-visible send pressure without forcing the app to poll stats constantly.

```cpp
client.on_backpressure([](const scn::BackpressureInfo& info) {
  // drop cosmetic updates, reduce snapshot rate, etc.
});

server.on_backpressure([](scn::Server::Peer peer, const scn::BackpressureInfo& info) {
  // per-peer response
});
```

## Codec helper

`BinaryWriter` and `BinaryReader` provide a small network-order codec for applications that do not want packed structs.

```cpp
std::array<scn::U8, 64> buf{};
scn::BinaryWriter w{std::span<scn::U8>(buf.data(), buf.size())};
w.u32(player_id);
w.i16(x);
w.i16(y);

scn::BinaryReader r{std::span<const scn::U8>(buf.data(), w.size())};
```

## Local in-process demo session

`LocalSession` owns one `IoContext`, one `Server`, and one `Client`. It is intended for demos and tests that need host mode in one process.

```cpp
scn::LocalSession session;
session.listen_and_connect(27015);
session.client().send_latest(1, PlayerInput{});
```

## Message routers

For more than a few message types, use `ClientRouter` or `ServerRouter` instead of repeating a manual `switch` in every `on_message` callback.

```cpp
scn::ServerRouter routes;
routes.on_text(1, [](scn::Server::Peer peer, std::string_view text) {
  return peer.send_ordered_text(1, text);
});
routes.on_binary<PlayerInput>(2, [](scn::Server::Peer peer, const PlayerInput& input) {
  return peer.send_latest(3, input);
});
routes.attach(server);
```

Routes may return `void` or `Result`. `Result`-returning routes let the application centralize dispatch failures with `on_error`.

## Request/reply transactions

`request_reply.hpp` adds a small application-level envelope for correlated transactions. It uses normal securecnet messages underneath, so reliability, ordering, fragmentation, encryption, replay defense, and backpressure still apply.

```cpp
scn::ClientRequestTable requests;
scn::ClientRouter routes;

routes.on(scn::RequestReplyDefaultMessageType, [&](const scn::MsgView& msg) -> scn::Result {
  return requests.dispatch(msg).rc;
});
routes.attach(client);

auto pending = requests.request(client, 11, payload, 2500);
```

Server code parses the envelope and replies through the peer:

```cpp
scn::RequestReplyFrame request{};
auto rc = scn::read_request_reply_frame(msg, request);
if (rc.ok()) {
  rc = scn::send_response(peer, request, response_payload);
}
```
