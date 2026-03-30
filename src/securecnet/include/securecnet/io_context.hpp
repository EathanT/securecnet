#pragma once 

#include "securecnet/result.hpp"
#include "securecnet/socket_init.hpp"
#include <chrono>
#include <deque>
#include <functional>
#include <thread>
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
		~IoContext() = default;

		IoContext(const IoContext&) = delete;
		IoContext& operator=(const IoContext&) = delete;

		Result runtime_status() const { return _runtime.status(); }

		void post(std::function<void()> fn);

		Result poll();
		Result run();

		template <class Rep, class Period>
		Result run_for(const std::chrono::duration<Rep, Period>& duration) {
			return run_until(std::chrono::steady_clock::now() + duration);
		}

		template <class Clock, class Duration>
		Result run_until(const std::chrono::time_point<Clock, Duration>& deadline) {
			if (!_runtime.status().ok()) {
				return _runtime.status();
			}

			_stop_requested = false;
			while (!_stop_requested && Clock::now() < deadline) {
				auto rc = poll();
				if (!rc.ok()) {
					return rc;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}

			return Result::success();
		}

		void stop() { _stop_requested = true; }
		void restart() { _stop_requested = false; }
		bool stopped() const { return _stop_requested; }

	private:
		friend class Client;
		friend class Server;

		void register_service(IoContextService* service);
		void unregister_service(IoContextService* service);
		Result drain_posted();

		SocketInit _runtime{};
		std::vector<IoContextService*> _services{};
		std::deque<std::function<void()>> _posted{};
		bool _stop_requested{ false };

	};

	using io_context = IoContext;

}