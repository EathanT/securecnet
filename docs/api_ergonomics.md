# Streamlined API guide

securecnet still exposes the low-level message-oriented UDP transport, but normal applications should start with the ergonomic surface.

## Delivery helpers

Use these helpers instead of hand-building `SendOptions` for common cases:

| Helper | Channel | Use it for |
| --- | --- | --- |
| `send_unreliable` / `send_unreliable_text` | `Unreliable` | telemetry, repeated state, disposable messages |
| `send_latest` / `send_latest_text` | `SequencedUnreliable` | latest-wins state such as position snapshots |
| `send_reliable` / `send_reliable_text` | `Reliable` | events where order does not matter |
| `send_ordered` / `send_ordered_text` | `ReliableOrdered` | chat, commands, transactions, ordered streams |
| `send_payload` | raw encrypted packet | advanced users with their own framing |

`Control` is reserved for internal ACK and fragment traffic. Application sends on `Control` are rejected.

## Typed callbacks

Use `on_text(type, callback)` when a message type is textual and does not need a manual `switch`:

```cpp
client.on_text(1, [](std::string_view text) {
  std::printf("message: %.*s\n", static_cast<int>(text.size()), text.data());
});
```

The generic `on_message` callback still receives all messages.

## Lifecycle callbacks

Clients now expose:

```cpp
client.on_connected([] {});
client.on_disconnected([](scn::CloseReason reason) {});
client.on_state_change([](scn::ConnectionState old_state, scn::ConnectionState new_state) {});
client.on_error([](scn::Result rc) {});
```

Servers expose:

```cpp
server.on_peer_connected([](scn::Server::Peer peer) {});
server.on_peer_disconnected([](scn::Server::Peer peer, scn::CloseReason reason) {});
server.on_peer_state_change([](scn::Server::Peer peer, scn::ConnectionState old_state, scn::ConnectionState new_state) {});
```

## Async wrappers

`AsyncClient` and `AsyncServer` own an `IoContext`, start the background loop on first use, and stop/join in their destructors. They do not change the underlying owner-thread model; they just make the correct pattern harder to misuse.

```cpp
scn::AsyncClient client;
client.client().on_text(1, [](std::string_view text) {});

client.connect("127.0.0.1", 27015).get();
client.send_ordered_text(1, "hello").get();
client.close().get();
```

## Config presets

Start with a preset, then tune only when telemetry says you need it:

```cpp
auto client_cfg = scn::ClientConfig::low_latency();
auto server_cfg = scn::ServerConfig::public_internet();
```

Available presets:

- `ClientConfig::low_latency()`
- `ClientConfig::reliable_gameplay()`
- `ClientConfig::bulk_transfer()`
- `ServerConfig::public_internet()`
- `ServerConfig::lan_only()`
- `ServerConfig::bulk_transfer()`

Builder example:

```cpp
auto cfg = scn::ClientConfig::builder()
  .send_budget_bytes_per_second(512 * 1024)
  .ordered_receive_window(128)
  .build();
```


## Routers instead of message switches

Use `ClientRouter` and `ServerRouter` when the application protocol has multiple message types. This keeps parsing and dispatch policy in one reusable object.

```cpp
scn::ClientRouter routes;
routes.on_text(1, [](std::string_view text) {});
routes.on_binary<PlayerInput>(2, [](const PlayerInput& input) {});
routes.attach(client);
```

Routes can return `void` for simple handlers or `Result` for handlers that need to report protocol errors.

## Request/reply helper

`ClientRequestTable` and the request/reply frame helpers add correlated request/response behavior above normal securecnet messages. Use this for login/profile/query style traffic instead of inventing a request ID envelope in each application.

See `docs/routing_request_reply.md` and `examples/request_reply_example.cpp`.
