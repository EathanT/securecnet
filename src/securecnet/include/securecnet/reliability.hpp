#pragma once

#include <deque>
#include <limits>
#include <span>
#include <vector>

#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"
#include "securecnet/result.hpp"

namespace scn {
	// ack + ack_bits, resend queue, message IDs

	enum class ControlType : U8 {
		ReliableAck = 1,
	};

	struct ReliablePayloadView {
		U64 message_id{ 0 };
		const U8* data{ nullptr };
		U16 len{ 0 };

		std::span<const U8> bytes() const {
			if (!data || len == 0) {
				return {};
			}
			return std::span<const U8>(data, len);
		}
	};

	inline Result write_reliable_payload(ByteWriter& w, U64 message_id, const void* data, U16 len) {
		if (len > static_cast<U16>(NetConfig::MaxReliableMessageBytes)) {
			return Result::fail(Errc::InvalidArg, "reliable message too large");
		}
		if (len > 0 && !data) {
			return Result::fail(Errc::InvalidArg, "reliable data is null");
		}

		Result rc = w.write_u64(message_id);
		if (!rc.ok()) {
			return rc;
		}

		if (len > 0) {
			rc = w.write_bytes(data, len);
			if (!rc.ok()) {
				return rc;
			}
		}

		return Result::success(); 
	}


	inline Result read_reliable_payload(ByteReader& r, ReliablePayloadView& out) {
		out = {};

		if (r.remaining() < sizeof(U64)) {
			return Result::fail(Errc::BadPacket, "reliable payload truncated");
		}

		Result rc = r.read_u64(out.message_id);
		if (!rc.ok()) {
			return rc;
		}

		const ST remaining = r.remaining();
		if (remaining > static_cast<ST>(U16_MAX)) {
			return Result::fail(Errc::BadPacket, "reliable payload too large");
		}

		out.len = static_cast<U16>(remaining);
		out.data = (remaining == 0) ? nullptr : r.peek_ptr(remaining);
		return r.skip(remaining);
	}

	inline Result write_reliable_ack(ByteWriter& w, U64 message_id) {
		return w.write_u64(message_id); 
	}

	inline Result read_reliable_ack(ByteReader& r, U64& message_id) {
		Result rc = r.read_u64(message_id);
		if (!rc.ok()) {
			return rc;
		}

		if (r.remaining() != 0) {
			return Result::fail(Errc::BadPacket, "extra bytes in reliable ack");
		}
		
		return Result::success();
	}

	class ReliableReceiveWindow {
	public:
		bool accept(U64 message_id) {
			if (!_initialized) {
				_initialized = true;
				_latest = message_id;
				_seen = 1ull;
				return true;
			}

			if (message_id > _latest) {
				const U64 delta = message_id - _latest;
				if (delta >= 64) {
					_seen = 0ull;
				}
				else {
					_seen <<= delta;
				}
				
				_seen |= 1ull;
				_latest = message_id;
				return true;
			}

			const U64 delta = _latest - message_id;
			if (delta >= 64) {
				return false;
			}

			const U64 mask = (1ull << delta);
			const bool duplicate = (_seen & mask) != 0;
			_seen |= mask;
			return !duplicate; 
		}

		bool seen(U64 message_id) const {
			if (!_initialized || message_id > _latest) {
				return false;
			}

			const U64 delta = _latest - message_id;
			if (delta >= 64) {
				return false;
			}

			const U64 mask = (1ull << delta);
			return (_seen & mask) != 0;
		}

		void reset() {
			_initialized = false;
			_latest = 0;
			_seen = 0;
		}

		U64 lastest() const {
			return _latest;
		}

	private: 
		bool _initialized{ false };
		U64 _latest{ 0 };
		U64 _seen{ 0 };
	};


	struct PendingReliableMessage {
		U64 message_id{ 0 };
		U8 user_type{ 0 };
		std::vector<U8> encoded_payload{};
		U64 last_send_ms{ 0 };
		U32 send_count{ 0 };
	};

	class ReliableSession {
	public:
		Result enqueue(U8 user_type, const void* data, U16 len, PendingReliableMessage& out) {
			out = {};
			out.message_id = _next_message_id++;
			out.user_type = user_type;
			out.encoded_payload.resize(sizeof(U64) + len);

			ByteWriter writer{ out.encoded_payload.data(), out.encoded_payload.size() };
			auto rc = write_reliable_payload(writer, out.message_id, data, len);
			if (!rc.ok()) {
				return rc;
			}

			_pending.push_back(out);
			return Result::success();
		}

		bool acknowledge(U64 message_id) {
			for (auto it = _pending.begin(); it != _pending.end(); ++it) {
				if (it->message_id == message_id) {
					_pending.erase(it);
					return true;
				}
			}
			return false;
		}

		template <class Fn>
		Result resend_due(U64 now_ms, U64 resend_delay_ms, Fn&& fn) {
			for (auto& pending : _pending) {
				const bool due = (pending.last_send_ms == 0) || ((now_ms - pending.last_send_ms) >= resend_delay_ms);
				if (!due) {
					continue;
				}

				auto rc = fn(pending);
				if (!rc.ok()) {
					return rc;
				}

				pending.last_send_ms = now_ms;
				++pending.send_count;
			}

			return Result::success(); 
		}

		void note_sent(U64 message_id, U64 now_ms) {
			for (auto& pending : _pending) {
				if (pending.message_id == message_id) {
					pending.last_send_ms = now_ms;
					++pending.send_count;
					return;
				}
			}
		}

		void clear() {
			_next_message_id = 1;
			_pending.clear();
			_received.reset();
		}

		bool accept_incoming(U64 message_id) {
			return _received.accept(message_id);
		}

		bool seen_incoming(U64 message_id) const {
			return _received.seen(message_id); 
		}

		ST pending_count() const {
			return _pending.size();
		}

		const std::deque<PendingReliableMessage>& pending() const {
			return _pending;
		}

	private:
		U64 _next_message_id{ 1 };
		std::deque<PendingReliableMessage> _pending{};
		ReliableReceiveWindow _received{};
	};

}