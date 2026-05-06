#include "securecnet/io_context.hpp"

#include <algorithm>

namespace scn {

	IoContext::~IoContext() {
		stop();
		if (_worker.joinable()) {
			if (_worker.get_id() == std::this_thread::get_id()) {
				_worker.detach();
			} else {
				_worker.join();
			}
		}
	}
	
	void IoContext::post(std::function<void()> fn) {
		if (!fn) {
			return;
		}

		{
			std::lock_guard<std::mutex> lock(_mutex);
			_posted.push_back(std::move(fn));
		}
		_cv.notify_one();
	}

	void IoContext::register_service(IoContextService* service) {
		if (!service) {
			return; 
		}

		std::lock_guard<std::mutex> lock(_mutex);
		const auto it = std::find(_services.begin(), _services.end(), service);
		if (it == _services.end()) {
			_services.push_back(service);
		}
		_cv.notify_one();
	}

	void IoContext::unregister_service(IoContextService* service) {
		if (!service) {
			return;
		}

		std::lock_guard<std::mutex> lock(_mutex);
		_services.erase(std::remove(_services.begin(), _services.end(), service), _services.end());
	}

	Result IoContext::drain_posted() {
		for (;;) {
			std::function<void()> fn;
			{
				std::lock_guard<std::mutex> lock(_mutex);
				if (_posted.empty()) {
					break;
				}
				fn = std::move(_posted.front());
				_posted.pop_front();
			}

			if (fn) {
				fn();
			}
		}

		return Result::success();
	}

	Result IoContext::poll() {
		if (!_runtime.status().ok()) {
			return _runtime.status(); 
		}

		auto rc = drain_posted();
		if (!rc.ok()) {
			return rc;
		}

		std::vector<IoContextService*> services;
		{
			std::lock_guard<std::mutex> lock(_mutex);
			services = _services;
		}
		for (IoContextService* service : services) {
			if (!service) {
				continue; 
			}

			rc = service->context_poll();
			if (!rc.ok()) {
				return rc;
			}
		}

		return drain_posted();
	}

	Result IoContext::run() {
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
		for (;;) {
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

	Result IoContext::run_async() {
		if (!_runtime.status().ok()) {
			return _runtime.status();
		}

		{
			std::lock_guard<std::mutex> lock(_mutex);
			if (_running || _worker.joinable()) {
				return Result::fail(Errc::StateError, "IoContext async runner is already active");
			}
		}

		try {
			_worker = std::thread([this]() {
				const Result rc = run();
				{
					std::lock_guard<std::mutex> lock(_mutex);
					_run_result = rc;
				}
				_cv.notify_all();
			});
		} catch (...) {
			return Result::fail(Errc::Internal, "failed to start IoContext worker thread");
		}

		std::unique_lock<std::mutex> lock(_mutex);
		_cv.wait(lock, [this]() { return _running; });
		return Result::success();
	}

	Result IoContext::join() {
		if (!_worker.joinable()) {
			std::lock_guard<std::mutex> lock(_mutex);
			return _run_result;
		}

		if (_worker.get_id() == std::this_thread::get_id()) {
			return Result::fail(Errc::StateError, "IoContext cannot join its own worker thread");
		}

		_worker.join();
		std::lock_guard<std::mutex> lock(_mutex);
		return _run_result;
	}

	void IoContext::stop() {
		{
			std::lock_guard<std::mutex> lock(_mutex);
			_stop_requested = true;
		}
		_cv.notify_all();
	}

	void IoContext::restart() {
		std::lock_guard<std::mutex> lock(_mutex);
		_stop_requested = false;
	}

	bool IoContext::stopped() const {
		std::lock_guard<std::mutex> lock(_mutex);
		return _stop_requested;
	}

	bool IoContext::running() const {
		std::lock_guard<std::mutex> lock(_mutex);
		return _running;
	}


}