# Routing and request/reply helpers

securecnet remains a transport library. The routing helpers sit above the encrypted message layer and remove common application glue without changing the wire protocol.

## Message routers

`ClientRouter` and `ServerRouter` dispatch by application message type. They are useful when an application has many message types and does not want one large manual switch in `on_message`.

```cpp
scn::Client client;
scn::ClientRouter routes;

routes.on_text(1, [](std::string_view text) {
  // chat message
});

routes.on_binary<PlayerInput>(2, [](const PlayerInput& input) {
  // size-checked binary message
});

routes.on_unhandled([](const scn::MsgView& msg) {
  // optional fallback
});

routes.attach(client);
```

Server routing includes the peer handle:

```cpp
scn::ServerRouter routes;
routes.on_text(1, [](scn::Server::Peer peer, std::string_view text) {
  return peer.send_ordered_text(1, text);
});
routes.attach(server);
```

Handlers may return `void` or `scn::Result`. Returning `Result` lets a route fail explicitly and lets `on_error` collect dispatch failures. The router owns the callback table; it must outlive the client/server callback it is attached to.

## Request/reply envelope

The request/reply helper is a small application-level envelope for reliable transactions. It is intentionally separate from the core transport so applications can use it only when they need correlated requests.

Default envelope message type: `scn::RequestReplyDefaultMessageType` (`250`). The application request type lives inside the envelope.

Frame fields:

| Field | Purpose |
| --- | --- |
| version | request/reply helper frame version, currently `1` |
| kind | request, response, or error |
| request_id | nonzero correlation ID |
| type | application request type |
| payload length | request/response payload length |
| payload | application bytes |

Client-side usage:

```cpp
scn::ClientRequestTable requests;
scn::ClientRouter routes;

routes.on(scn::RequestReplyDefaultMessageType, [&](const scn::MsgView& msg) -> scn::Result {
  return requests.dispatch(msg).rc;
});
routes.attach(client);

auto future = requests.request(client, 11, payload, 2500);
```

Server-side usage:

```cpp
routes.on(scn::RequestReplyDefaultMessageType, [](scn::Server::Peer peer, const scn::MsgView& msg) {
  scn::RequestReplyFrame request{};
  auto rc = scn::read_request_reply_frame(msg, request);
  if (!rc.ok()) return rc;
  return scn::send_response(peer, request, response_payload);
});
```

## Why this is not built into the core packet protocol

Request/reply is an application semantic. Keeping it above the message layer avoids consuming packet grammar space, avoids forcing all users into one RPC model, and keeps the security-critical transport smaller. The helper still benefits from securecnet reliability, ordering, fragmentation, encryption, replay defense, and backpressure because it sends through normal `send` paths.
