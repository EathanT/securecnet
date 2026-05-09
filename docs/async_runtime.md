# Async runtime support

securecnet remains an event-loop based transport, but `IoContext` now has a small asynchronous runner for applications that want the networking loop to live on a dedicated thread.

## What changed

`IoContext` now provides:

- `run_async()` - starts the context loop on one owned worker thread.
- `stop()` - requests loop shutdown from any thread.
- `join()` - waits for the worker and returns the loop result.
- `restart()` - clears a previous stop request before a new run.
- `running()` and `stopped()` - thread-safe status helpers.
- `post(std::function<void()>)` - thread-safe callback dispatch into the context owner thread.
- `try_post(std::function<void()>)` - bounded callback dispatch that reports `QueueFull` instead of silently growing forever.
- `post_task(fn)` - posts a callable and returns a `std::future` for its result or exception.
- `posted_count()` - returns the current queued callback count.

The async runner is intentionally small. It does not turn `Client` or `Server` into internally synchronized objects. Instead, it gives applications a safe way to marshal work onto the single transport owner thread. For convenience, `AsyncClient` and `AsyncServer` wrap this pattern and own the stop/join lifecycle.

## Correct usage pattern

Create the networking objects, start the context, and perform transport operations through posted callbacks:

```cpp
scn::IoContext io;
scn::Server server(io);
scn::Client client(io);

server.listen(27015);
client.connect({"127.0.0.1", 27015});

io.run_async();

auto send_result = io.post_task([&] {
  scn::SendOptions options{};
  options.channel = scn::Channel::ReliableOrdered;
  return client.send_text(1, "hello", options);
});

const scn::Result rc = send_result.get();

io.stop();
io.join();
```

## Lifetime rule

Services registered with an `IoContext` must outlive the running context loop. Stop and join the context before destroying a `Client`, `Server`, or other `IoContextService` registered with it.

```cpp
io.stop();
io.join();
// It is now safe to destroy Client and Server objects.
```

Destroying a service while a background `IoContext` is still polling is a use-after-free risk in any event-loop design that stores service pointers.

## Concurrency boundary

The following operations are safe from other threads:

- `IoContext::post`
- `IoContext::post_task`
- `IoContext::stop`
- `IoContext::join` from a non-worker thread
- `IoContext::running`
- `IoContext::stopped`

Transport methods such as `Client::send`, `Client::connect`, `Server::listen`, and peer operations should still be called on the context owner thread. Use `post`, `try_post`, or `post_task` when calling them from application worker threads, or use `AsyncClient` / `AsyncServer` for the common lifecycle.

## Example and benchmark

The repository includes:

- `examples/async_echo_example.cpp` - end-to-end async client/server echo using `run_async` and `post_task`.
- `bench/bench_async_io_context.cpp` - posted callback throughput benchmark.
- `tests/test_async.cpp` - unit and integration tests for the async runner.

## Snippet validation

The `docs/snippets` targets compile the documented basic client, async client, and server usage paths so examples do not drift from the public API.
