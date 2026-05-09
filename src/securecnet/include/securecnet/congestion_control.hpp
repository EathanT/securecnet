#pragma once

#include <algorithm>

#include "securecnet/config.hpp"
#include "securecnet/util/util.h"

namespace scn {

    struct CongestionControlSnapshot {
        bool enabled{ false };
        U64 current_rate_bytes_per_second{ 0 };
        U64 current_window_bytes{ 0 };
        U64 ack_events{ 0 };
        U64 loss_events{ 0 };
        U64 backpressure_events{ 0 };
    };

    class CongestionController {
    public:
        void configure(const CongestionControlConfig& cfg, U32 configured_send_rate_bytes_per_second) {
            _cfg = cfg;
            _configured_send_rate = (std::max<U64>)(1, configured_send_rate_bytes_per_second);
            reset_runtime();
        }

        void reset_runtime() {
            const U64 max_rate = configured_max_rate();
            const U64 min_rate = configured_min_rate(max_rate);
            const U64 initial_rate = _cfg.initial_rate_bytes_per_second != 0
                ? _cfg.initial_rate_bytes_per_second
                : (std::max<U64>)(min_rate, max_rate / 2);

            _current_rate = _cfg.enabled
                ? std::clamp<U64>(initial_rate, min_rate, max_rate)
                : _configured_send_rate;
            _smoothed_rtt_ms = 100;
            _latest_rtt_ms = 0;
            _last_loss_ms = 0;
            _last_backpressure_ms = 0;
            _ack_events = 0;
            _loss_events = 0;
            _backpressure_events = 0;
            update_window();
        }

        bool enabled() const {
            return _cfg.enabled;
        }

        U64 rate_bytes_per_second() const {
            return _cfg.enabled ? _current_rate : _configured_send_rate;
        }

        U64 window_bytes() const {
            return _cfg.enabled ? _current_window : bucket_cap_bytes();
        }

        U64 bucket_cap_bytes() const {
            const U64 two_seconds = rate_bytes_per_second() * 2;
            return (std::max<U64>)(NetConfig::MaxPacketBytes, two_seconds);
        }

        void on_ack(bool rtt_sample_valid, U64 rtt_sample_ms, bool retransmitted, U64 now_ms) {
            if (!_cfg.enabled) {
                return;
            }
            (void)now_ms;
            ++_ack_events;
            if (rtt_sample_valid && rtt_sample_ms > 0) {
                _latest_rtt_ms = rtt_sample_ms;
                if (_smoothed_rtt_ms == 0) {
                    _smoothed_rtt_ms = rtt_sample_ms;
                } else {
                    _smoothed_rtt_ms = ((_smoothed_rtt_ms * 7) + rtt_sample_ms) / 8;
                }
            }
            if (!retransmitted) {
                const U64 max_rate = configured_max_rate();
                const U64 increase = (std::max<U64>)(1, _cfg.additive_increase_bytes_per_ack);
                _current_rate = (std::min<U64>)(max_rate, _current_rate + increase);
                update_window();
            }
        }

        void on_loss(U64 now_ms, U64 count = 1) {
            if (!_cfg.enabled || count == 0) {
                return;
            }
            _loss_events += count;
            if (_last_loss_ms != 0 && now_ms >= _last_loss_ms && (now_ms - _last_loss_ms) < _cfg.loss_cooldown_ms) {
                return;
            }
            _last_loss_ms = now_ms;
            apply_decrease(_cfg.multiplicative_decrease_per_mille);
        }

        void on_backpressure(U64 now_ms) {
            if (!_cfg.enabled) {
                return;
            }
            ++_backpressure_events;
            if (_last_backpressure_ms != 0 && now_ms >= _last_backpressure_ms &&
                (now_ms - _last_backpressure_ms) < _cfg.backpressure_cooldown_ms) {
                return;
            }
            _last_backpressure_ms = now_ms;
            apply_decrease(_cfg.backpressure_decrease_per_mille);
        }

        CongestionControlSnapshot snapshot() const {
            return CongestionControlSnapshot{
                _cfg.enabled,
                rate_bytes_per_second(),
                window_bytes(),
                _ack_events,
                _loss_events,
                _backpressure_events,
            };
        }

    private:
        U64 configured_max_rate() const {
            if (!_cfg.enabled) {
                return _configured_send_rate;
            }
            return _cfg.max_rate_bytes_per_second == 0
                ? _configured_send_rate
                : static_cast<U64>(_cfg.max_rate_bytes_per_second);
        }

        U64 configured_min_rate(U64 max_rate) const {
            if (!_cfg.enabled) {
                return _configured_send_rate;
            }
            return (std::min<U64>)((std::max<U64>)(1, _cfg.min_rate_bytes_per_second), max_rate);
        }

        U64 configured_max_window(U64 max_rate) const {
            if (_cfg.max_window_bytes != 0) {
                return _cfg.max_window_bytes;
            }
            return (std::max<U64>)(_cfg.min_window_bytes, max_rate * 2);
        }

        void apply_decrease(U32 decrease_per_mille) {
            const U64 max_rate = configured_max_rate();
            const U64 min_rate = configured_min_rate(max_rate);
            const U64 decreased = (_current_rate * decrease_per_mille) / 1000;
            _current_rate = std::clamp<U64>((std::max<U64>)(1, decreased), min_rate, max_rate);
            update_window();
        }

        void update_window() {
            if (!_cfg.enabled) {
                _current_window = bucket_cap_bytes();
                return;
            }
            const U64 max_rate = configured_max_rate();
            const U64 rtt_ms = (std::max<U64>)(25, _smoothed_rtt_ms == 0 ? 100 : _smoothed_rtt_ms);
            const U64 bandwidth_delay_product = (std::max<U64>)(NetConfig::MaxPacketBytes,
                                                              (_current_rate * rtt_ms) / 1000);
            const U64 max_window = configured_max_window(max_rate);
            _current_window = std::clamp<U64>(bandwidth_delay_product,
                                              static_cast<U64>(_cfg.min_window_bytes),
                                              max_window);
        }

        CongestionControlConfig _cfg{};
        U64 _configured_send_rate{ 1 };
        U64 _current_rate{ 1 };
        U64 _current_window{ NetConfig::MaxPacketBytes * 4 };
        U64 _latest_rtt_ms{ 0 };
        U64 _smoothed_rtt_ms{ 100 };
        U64 _last_loss_ms{ 0 };
        U64 _last_backpressure_ms{ 0 };
        U64 _ack_events{ 0 };
        U64 _loss_events{ 0 };
        U64 _backpressure_events{ 0 };
    };

} // namespace scn
