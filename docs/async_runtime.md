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
- `post_task(fn)` - posts a callable and returns a `std::future` for its result or exception.

The async runner is intentionally small. It does not turn `Client` or `Server` into internally synchronized objects. Instead, it gives applications a safe way to marshal work onto the single transport owner thread.

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

Transport methods such as `Client::send`, `Client::connect`, `Server::listen`, and peer operations should still be called on the context owner thread. Use `post` or `post_task` when calling them from application worker threads.

## Example and benchmark

The repository includes:

- `examples/async_echo_example.cpp` - end-to-end async client/server echo using `run_async` and `post_task`.
- `bench/bench_async_io_context.cpp` - posted callback throughput benchmark.
- `tests/test_async.cpp` - unit and integration tests for the async runner.
