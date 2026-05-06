#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <span>
#include <vector>

#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"
#include "securecnet/message.hpp"
#include "securecnet/result.hpp"

namespace scn {

    enum class ControlType : U8 {
        ReliableAck = 1,
        Fragment = 2,
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

    struct OrderedPayloadView {
        U64 delivery_sequence{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };
    };

    struct SequencedPayloadView {
        U64 delivery_sequence{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };
    };

    inline Result write_reliable_payload(ByteWriter& w, U64 message_id, const void* data, U16 len) {
        if (message_id == 0) {
            return Result::fail(Errc::InvalidArg, "reliable message id must be non-zero");
        }
        if (len > static_cast<U16>(NetConfig::MaxReliableMessageBytes)) {
            return Result::fail(Errc::InvalidArg, "reliable message too large");
        }
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "reliable data is null");
        }
        Result rc = w.write_u64(message_id);
        if (!rc.ok()) return rc;
        if (len > 0) {
            rc = w.write_bytes(data, len);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_reliable_payload(ByteReader& r, ReliablePayloadView& out) {
        out = {};
        if (r.remaining() < static_cast<ST>(sizeof(U64))) {
            return Result::fail(Errc::BadPacket, "reliable payload truncated");
        }
        Result rc = r.read_u64(out.message_id);
        if (!rc.ok()) return rc;
        if (out.message_id == 0) {
            return Result::fail(Errc::BadPacket, "reliable message id is invalid");
        }
        const ST remaining = r.remaining();
        if (remaining > static_cast<ST>(U16_MAX)) {
            return Result::fail(Errc::BadPacket, "reliable payload too large");
        }
        out.len = static_cast<U16>(remaining);
        out.data = (remaining == 0) ? nullptr : r.peek_ptr(remaining);
        return r.skip(remaining);
    }

    inline Result write_ordered_payload(ByteWriter& w, U64 delivery_sequence, const void* data, U16 len) {
        if (delivery_sequence == 0) {
            return Result::fail(Errc::InvalidArg, "ordered sequence must be non-zero");
        }
        if (len > static_cast<U16>(NetConfig::MaxOrderedMessageBytes)) {
            return Result::fail(Errc::InvalidArg, "ordered message too large");
        }
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "ordered data is null");
        }
        Result rc = w.write_u64(delivery_sequence);
        if (!rc.ok()) return rc;
        if (len > 0) {
            rc = w.write_bytes(data, len);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_ordered_payload(ByteReader& r, OrderedPayloadView& out) {
        out = {};
        if (r.remaining() < static_cast<ST>(sizeof(U64))) {
            return Result::fail(Errc::BadPacket, "ordered payload truncated");
        }
        Result rc = r.read_u64(out.delivery_sequence);
        if (!rc.ok()) return rc;
        if (out.delivery_sequence == 0) {
            return Result::fail(Errc::BadPacket, "ordered payload has invalid sequence");
        }
        const ST remaining = r.remaining();
        if (remaining > static_cast<ST>(U16_MAX)) {
            return Result::fail(Errc::BadPacket, "ordered payload too large");
        }
        out.len = static_cast<U16>(remaining);
        out.data = (remaining == 0) ? nullptr : r.peek_ptr(remaining);
        return r.skip(remaining);
    }

    inline Result write_sequenced_payload(ByteWriter& w, U64 delivery_sequence, const void* data, U16 len) {
        if (delivery_sequence == 0) {
            return Result::fail(Errc::InvalidArg, "sequenced delivery sequence must be non-zero");
        }
        if (len > static_cast<U16>(NetConfig::MaxSequencedMessageBytes)) {
            return Result::fail(Errc::InvalidArg, "sequenced message too large");
        }
        if (len > 0 && !data) {
            return Result::fail(Errc::InvalidArg, "sequenced data is null");
        }
        Result rc = w.write_u64(delivery_sequence);
        if (!rc.ok()) return rc;
        if (len > 0) {
            rc = w.write_bytes(data, len);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_sequenced_payload(ByteReader& r, SequencedPayloadView& out) {
        out = {};
        if (r.remaining() < static_cast<ST>(sizeof(U64))) {
            return Result::fail(Errc::BadPacket, "sequenced payload truncated");
        }
        Result rc = r.read_u64(out.delivery_sequence);
        if (!rc.ok()) return rc;
        if (out.delivery_sequence == 0) {
            return Result::fail(Errc::BadPacket, "sequenced payload has invalid sequence");
        }
        const ST remaining = r.remaining();
        if (remaining > static_cast<ST>(U16_MAX)) {
            return Result::fail(Errc::BadPacket, "sequenced payload too large");
        }
        out.len = static_cast<U16>(remaining);
        out.data = (remaining == 0) ? nullptr : r.peek_ptr(remaining);
        return r.skip(remaining);
    }

    inline Result write_reliable_ack(ByteWriter& w, Channel channel, U64 message_id) {
        if (!channel_is_reliable(channel)) {
            return Result::fail(Errc::InvalidArg, "ack channel must be reliable");
        }
        if (message_id == 0) {
            return Result::fail(Errc::InvalidArg, "ack message id must be non-zero");
        }
        Result rc = w.write_u8(static_cast<U8>(channel));
        if (!rc.ok()) return rc;
        return w.write_u64(message_id);
    }

    inline Result read_reliable_ack(ByteReader& r, Channel& channel, U64& message_id) {
        U8 raw_channel = 0;
        Result rc = r.read_u8(raw_channel);
        if (!rc.ok()) return rc;
        if (raw_channel != static_cast<U8>(Channel::Reliable) &&
            raw_channel != static_cast<U8>(Channel::ReliableOrdered)) {
            return Result::fail(Errc::BadPacket, "ack channel is invalid");
        }
        channel = static_cast<Channel>(raw_channel);
        rc = r.read_u64(message_id);
        if (!rc.ok()) return rc;
        if (message_id == 0) {
            return Result::fail(Errc::BadPacket, "ack message id is invalid");
        }
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in reliable ack");
        }
        return Result::success();
    }

    inline Result write_reliable_ack(ByteWriter& w, U64 message_id) {
        return write_reliable_ack(w, Channel::Reliable, message_id);
    }

    inline Result read_reliable_ack(ByteReader& r, U64& message_id) {
        Channel channel = Channel::Reliable;
        auto rc = read_reliable_ack(r, channel, message_id);
        if (!rc.ok()) {
            return rc;
        }
        if (channel != Channel::Reliable) {
            return Result::fail(Errc::BadPacket, "legacy ack reader expected reliable channel");
        }
        return Result::success();
    }

    class ReliableReceiveWindow {
    public:
        bool accept(U64 message_id) {
            if (message_id == 0) {
                return false;
            }
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
                } else {
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
            if (message_id == 0) {
                return false;
            }
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

        U64 latest() const {
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
        SendPriority priority{ SendPriority::Normal };
        U64 lifetime_ms{ 0 };
        U64 enqueued_ms{ 0 };
        U64 first_send_ms{ 0 };
        U64 last_send_ms{ 0 };
        U64 rto_ms{ 0 };
        U32 send_count{ 0 };
        bool inflight{ false };
    };

    struct ReliableAckEvent {
        bool removed{ false };
        bool rtt_sample_valid{ false };
        U64 rtt_sample_ms{ 0 };
        bool retransmitted{ false };
    };

    class ReliableSession {
    public:
        void configure(const ReliabilityConfig& cfg) {
            _cfg = cfg;
            reset_rtt();
        }

        Result enqueue(U8 user_type, const void* data, U16 len,
                       SendPriority priority, U64 lifetime_ms, U64 now_ms,
                       PendingReliableMessage& out) {
            if (_pending.size() >= _cfg.max_pending_messages) {
                return Result::fail(Errc::QueueFull, "reliable queue full");
            }
            const U32 new_bytes = static_cast<U32>(sizeof(U64) + len);
            if ((_pending_bytes + new_bytes) > _cfg.max_pending_bytes) {
                return Result::fail(Errc::QueueFull, "reliable byte budget exhausted");
            }

            out = {};
            out.message_id = _next_message_id++;
            out.user_type = user_type;
            out.priority = priority;
            out.lifetime_ms = lifetime_ms;
            out.enqueued_ms = now_ms;
            out.rto_ms = _rto_ms;
            out.encoded_payload.resize(sizeof(U64) + len);

            ByteWriter writer{ out.encoded_payload.data(), out.encoded_payload.size() };
            auto rc = write_reliable_payload(writer, out.message_id, data, len);
            if (!rc.ok()) {
                return rc;
            }

            auto insert_pos = _pending.end();
            for (auto it = _pending.begin(); it != _pending.end(); ++it) {
                if (static_cast<U8>(it->priority) < static_cast<U8>(priority)) {
                    insert_pos = it;
                    break;
                }
            }
            _pending.insert(insert_pos, out);
            _pending_bytes += new_bytes;
            return Result::success();
        }

        Result enqueue(U8 user_type, const void* data, U16 len, PendingReliableMessage& out) {
            return enqueue(user_type, data, len, SendPriority::Normal, 0, 0, out);
        }

        ReliableAckEvent acknowledge(U64 message_id, U64 now_ms) {
            ReliableAckEvent event{};
            for (auto it = _pending.begin(); it != _pending.end(); ++it) {
                if (it->message_id != message_id) {
                    continue;
                }
                event.removed = true;
                event.retransmitted = it->send_count > 1;
                if (it->inflight && _inflight_count > 0) {
                    --_inflight_count;
                }
                if (it->send_count == 1 && it->first_send_ms != 0 && now_ms >= it->first_send_ms) {
                    event.rtt_sample_valid = true;
                    event.rtt_sample_ms = now_ms - it->first_send_ms;
                    update_rtt(event.rtt_sample_ms);
                }
                _pending_bytes -= static_cast<U32>(it->encoded_payload.size());
                _pending.erase(it);
                return event;
            }
            return event;
        }

        bool acknowledge(U64 message_id) {
            return acknowledge(message_id, 0).removed;
        }

        template <class Fn>
        Result resend_due(U64 now_ms, Fn&& fn) {
            for (auto& pending : _pending) {
                if (pending.lifetime_ms > 0 && now_ms >= (pending.enqueued_ms + pending.lifetime_ms)) {
                    continue;
                }

                if (pending.inflight) {
                    if (pending.last_send_ms == 0 || (now_ms - pending.last_send_ms) < pending.rto_ms) {
                        continue;
                    }
                    ++_loss_events;
                    ++_retransmit_events;
                    pending.inflight = false;
                    if (_inflight_count > 0) {
                        --_inflight_count;
                    }
                    pending.rto_ms = std::min<U64>(_cfg.max_rto_ms, std::max<U64>(_cfg.min_rto_ms, pending.rto_ms * 2));
                }

                if (_inflight_count >= _cfg.max_inflight_messages) {
                    break;
                }

                auto rc = fn(pending);
                if (!rc.ok()) {
                    return rc;
                }

                if (pending.first_send_ms == 0) {
                    pending.first_send_ms = now_ms;
                }
                pending.last_send_ms = now_ms;
                ++pending.send_count;
                if (!pending.inflight) {
                    pending.inflight = true;
                    ++_inflight_count;
                }
            }
            update_loss_estimate();
            return Result::success();
        }

        template <class Fn>
        Result resend_due(U64 now_ms, U64 legacy_delay_ms, Fn&& fn) {
            for (auto& pending : _pending) {
                if (pending.lifetime_ms > 0 && now_ms >= (pending.enqueued_ms + pending.lifetime_ms)) {
                    continue;
                }
                if (pending.last_send_ms != 0 && (now_ms - pending.last_send_ms) < legacy_delay_ms) {
                    continue;
                }
                auto rc = fn(pending);
                if (!rc.ok()) {
                    return rc;
                }
                if (pending.first_send_ms == 0) {
                    pending.first_send_ms = now_ms;
                }
                pending.last_send_ms = now_ms;
                ++pending.send_count;
            }
            return Result::success();
        }

        U32 expire_old(U64 now_ms) {
            U32 removed = 0;
            for (auto it = _pending.begin(); it != _pending.end();) {
                if (it->lifetime_ms == 0 || now_ms < (it->enqueued_ms + it->lifetime_ms)) {
                    ++it;
                    continue;
                }
                if (it->inflight && _inflight_count > 0) {
                    --_inflight_count;
                }
                _pending_bytes -= static_cast<U32>(it->encoded_payload.size());
                it = _pending.erase(it);
                ++removed;
            }
            return removed;
        }

        bool note_sent(U64 message_id, U64 now_ms) {
            for (auto& pending : _pending) {
                if (pending.message_id != message_id) {
                    continue;
                }
                if (!pending.inflight) {
                    if (_inflight_count >= _cfg.max_inflight_messages) {
                        return false;
                    }
                    pending.inflight = true;
                    ++_inflight_count;
                }
                if (pending.first_send_ms == 0) {
                    pending.first_send_ms = now_ms;
                }
                pending.last_send_ms = now_ms;
                ++pending.send_count;
                return true;
            }
            return false;
        }

        void clear() {
            _next_message_id = 1;
            _pending.clear();
            _pending_bytes = 0;
            _inflight_count = 0;
            _received.reset();
            reset_rtt();
            _loss_events = 0;
            _retransmit_events = 0;
            _loss_per_mille = 0;
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

        U32 pending_bytes() const {
            return _pending_bytes;
        }

        U32 inflight_count() const {
            return _inflight_count;
        }

        const std::deque<PendingReliableMessage>& pending() const {
            return _pending;
        }

        U64 latest_rtt_ms() const {
            return _latest_rtt_ms;
        }

        U64 smoothed_rtt_ms() const {
            return _srtt_ms;
        }

        U64 rtt_variance_ms() const {
            return _rttvar_ms;
        }

        U64 rto_ms() const {
            return _rto_ms;
        }

        U64 loss_events() const {
            return _loss_events;
        }

        U64 retransmit_events() const {
            return _retransmit_events;
        }

        U64 loss_per_mille() const {
            return _loss_per_mille;
        }

    private:
        void reset_rtt() {
            _have_rtt = false;
            _latest_rtt_ms = 0;
            _srtt_ms = 0;
            _rttvar_ms = 0;
            _rto_ms = _cfg.initial_rto_ms;
        }

        void update_rtt(U64 sample_ms) {
            _latest_rtt_ms = sample_ms;
            if (!_have_rtt) {
                _have_rtt = true;
                _srtt_ms = sample_ms;
                _rttvar_ms = std::max<U64>(1, sample_ms / 2);
            } else {
                const U64 abs_delta = (_srtt_ms > sample_ms) ? (_srtt_ms - sample_ms) : (sample_ms - _srtt_ms);
                _rttvar_ms = ((_rttvar_ms * 3) + abs_delta) / 4;
                _srtt_ms = ((_srtt_ms * 7) + sample_ms) / 8;
            }
            const U64 penalty = std::max<U64>(1, _rttvar_ms * 4);
            _rto_ms = std::clamp<U64>(_srtt_ms + penalty, _cfg.min_rto_ms, _cfg.max_rto_ms);
        }

        void update_loss_estimate() {
            const U64 denom = std::max<U64>(1, _loss_events + (_next_message_id - 1));
            _loss_per_mille = std::min<U64>(1000, (_loss_events * 1000) / denom);
        }

        ReliabilityConfig _cfg{};
        U64 _next_message_id{ 1 };
        std::deque<PendingReliableMessage> _pending{};
        U32 _pending_bytes{ 0 };
        U32 _inflight_count{ 0 };
        ReliableReceiveWindow _received{};

        bool _have_rtt{ false };
        U64 _latest_rtt_ms{ 0 };
        U64 _srtt_ms{ 0 };
        U64 _rttvar_ms{ 0 };
        U64 _rto_ms{ 120 };
        U64 _loss_events{ 0 };
        U64 _retransmit_events{ 0 };
        U64 _loss_per_mille{ 0 };
    };

    class OrderedReceiveWindow {
    public:
        explicit OrderedReceiveWindow(U32 max_buffered = 64) : _max_buffered(max_buffered) {}

        void set_max_buffered(U32 max_buffered) {
            _max_buffered = max_buffered;
        }

        template <class DeliverFn>
        Result accept(U64 delivery_sequence, U8 type, const U8* data, U16 len,
                      DeliverFn&& deliver, bool& buffered, bool& stale) {
            buffered = false;
            stale = false;
            if (delivery_sequence == 0) {
                return Result::fail(Errc::BadPacket, "ordered sequence must be non-zero");
            }
            if (_next_expected == 0) {
                _next_expected = 1;
            }
            if (delivery_sequence < _next_expected) {
                stale = true;
                return Result::success();
            }
            if (delivery_sequence == _next_expected) {
                auto rc = deliver(type, data, len);
                if (!rc.ok()) {
                    return rc;
                }
                ++_next_expected;
                for (;;) {
                    auto it = _buffer.find(_next_expected);
                    if (it == _buffer.end()) {
                        break;
                    }
                    rc = deliver(it->second.type,
                                 it->second.payload.empty() ? nullptr : it->second.payload.data(),
                                 static_cast<U16>(it->second.payload.size()));
                    if (!rc.ok()) {
                        return rc;
                    }
                    _buffer.erase(it);
                    ++_next_expected;
                }
                return Result::success();
            }
            if (_buffer.find(delivery_sequence) != _buffer.end()) {
                stale = true;
                return Result::success();
            }
            if (_buffer.size() >= _max_buffered) {
                return Result::fail(Errc::QueueFull, "ordered receive buffer is full");
            }
            BufferedMessage entry{};
            entry.type = type;
            if (len > 0) {
                entry.payload.assign(data, data + len);
            }
            _buffer.emplace(delivery_sequence, std::move(entry));
            buffered = true;
            return Result::success();
        }

        void clear() {
            _next_expected = 1;
            _buffer.clear();
        }

        U64 next_expected() const {
            return _next_expected;
        }

        ST buffered_count() const {
            return _buffer.size();
        }

    private:
        struct BufferedMessage {
            U8 type{ 0 };
            std::vector<U8> payload{};
        };

        U64 _next_expected{ 1 };
        U32 _max_buffered{ 64 };
        std::map<U64, BufferedMessage> _buffer{};
    };

    class SequencedReceiveWindow {
    public:
        bool accept(U64 delivery_sequence) {
            if (delivery_sequence == 0) {
                return false;
            }
            if (!_initialized) {
                _initialized = true;
                _latest = delivery_sequence;
                return true;
            }
            if (delivery_sequence <= _latest) {
                return false;
            }
            _latest = delivery_sequence;
            return true;
        }

        void clear() {
            _initialized = false;
            _latest = 0;
        }

        U64 latest() const {
            return _latest;
        }

    private:
        bool _initialized{ false };
        U64 _latest{ 0 };
    };

} // namespace scn
