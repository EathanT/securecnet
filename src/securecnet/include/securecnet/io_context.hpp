#pragma once 

#include "securecnet/result.hpp"
#include "securecnet/socket_init.hpp"
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>


namespace scn {
	
	class IoContextService {
	public:
		virtual ~IoContextService() = default;
		virtual Result context_poll() = 0;
	};

	class IoContext {
	public:
		IoContext() = default;
		~IoContext();

		IoContext(const IoContext&) = delete;
		IoContext& operator=(const IoContext&) = delete;

		Result runtime_status() const { return _runtime.status(); }

		void post(std::function<void()> fn);

		template <class Fn>
		auto post_task(Fn&& fn) -> std::future<std::invoke_result_t<std::decay_t<Fn>&>> {
			using Task = std::decay_t<Fn>;
			using Return = std::invoke_result_t<Task&>;

			auto packaged = std::make_shared<std::packaged_task<Return()>>(Task(std::forward<Fn>(fn)));
			auto future = packaged->get_future();
			post([packaged]() mutable { (*packaged)(); });
			return future;
		}

		Result poll();
		Result run();
		Result run_async();
		Result join();

		template <class Rep, class Period>
		Result run_for(const std::chrono::duration<Rep, Period>& duration) {
			return run_until(std::chrono::steady_clock::now() + duration);
		}

		template <class Clock, class Duration>
		Result run_until(const std::chrono::time_point<Clock, Duration>& deadline) {
			if (!_runtime.status().ok()) {
				return _runtime.status();
			}

			{
				std::lock_guard<std::mutex> lock(_mutex);
				if (_running) {
					return Result::fail(Errc::StateError, "IoContext is already running");
				}
				_stop_requested = false;
				_running = true;
				_run_result = Result::success();
			}
			_cv.notify_all();

			Result result = Result::success();
			while (Clock::now() < deadline) {
				{
					std::lock_guard<std::mutex> lock(_mutex);
					if (_stop_requested) {
						break;
					}
				}

				auto rc = poll();
				if (!rc.ok()) {
					result = rc;
					break;
				}

				std::unique_lock<std::mutex> lock(_mutex);
				if (!_stop_requested && _posted.empty()) {
					_cv.wait_for(lock, std::chrono::milliseconds(1));
				}
			}

			{
				std::lock_guard<std::mutex> lock(_mutex);
				_running = false;
				_run_result = result;
			}
			_cv.notify_all();
			return result;
		}

		void stop();
		void restart();
		bool stopped() const;
		bool running() const;

	private:
		friend class Client;
		friend class Server;

		void register_service(IoContextService* service);
		void unregister_service(IoContextService* service);
		Result drain_posted();

		SocketInit _runtime{};
		std::vector<IoContextService*> _services{};
		std::deque<std::function<void()>> _posted{};
		mutable std::mutex _mutex{};
		std::condition_variable _cv{};
		std::thread _worker{};
		Result _run_result{};
		bool _running{ false };
		bool _stop_requested{ false };

	};

	using io_context = IoContext;

}