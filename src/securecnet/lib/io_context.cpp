#include "securecnet/io_context.hpp"

#include <algorithm>
#include <thread>

namespace scn {
	
	void IoContext::post(std::function<void()> fn) {
		if (!fn) {
			return;
		}

		_posted.push_back(std::move(fn));
	}

	void IoContext::register_service(IoContextService* service) {
		if (!service) {
			return; 
		}

		const auto it = std::find(_services.begin(), _services.end(), service);
		if (it == _services.end()) {
			_services.push_back(service);
		}
	}

	void IoContext::unregister_service(IoContextService* service) {
		if (!service) {
			return;
		}

		_services.erase(std::remove(_services.begin(), _services.end(), service), _services.end());
	}

	Result IoContext::drain_posted() {
		while (!_posted.empty()) {
			auto fn = std::move(_posted.front());
			_posted.pop_front();

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

		const auto services = _services;
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

		_stop_requested = false;
		while (!_stop_requested) {
			auto rc = poll();
			if (!rc.ok()) {
				return rc;
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}

		return Result::success();

	}


}