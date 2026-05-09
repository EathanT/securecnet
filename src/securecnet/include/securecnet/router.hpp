#pragma once

#include <array>
#include <functional>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>

#include "securecnet/client.hpp"
#include "securecnet/message.hpp"
#include "securecnet/result.hpp"
#include "securecnet/server.hpp"

namespace scn {

    struct RouteResult {
        bool handled{ false };
        Result rc{};

        constexpr bool ok() const { return rc.ok(); }
        constexpr explicit operator bool() const { return ok(); }

        static constexpr RouteResult unhandled() { return { false, Result::success() }; }
        static constexpr RouteResult success() { return { true, Result::success() }; }
        static constexpr RouteResult fail(Errc code, std::string_view msg = {}) {
            return { true, Result::fail(code, msg) };
        }
    };

    namespace detail {
        template <class Fn, class... Args>
        Result invoke_route_handler(Fn& fn, Args&&... args) {
            using Return = std::invoke_result_t<Fn&, Args...>;
            if constexpr (std::is_same_v<std::remove_cv_t<std::remove_reference_t<Return>>, Result>) {
                return std::invoke(fn, std::forward<Args>(args)...);
            } else {
                std::invoke(fn, std::forward<Args>(args)...);
                return Result::success();
            }
        }
    } // namespace detail

    class ClientRouter {
    public:
        using Handler = std::function<Result(const MsgView&)>;
        using FallbackHandler = std::function<Result(const MsgView&)>;
        using ErrorHandler = std::function<void(const MsgView&, Result)>;

        ClientRouter() = default;

        template <class Fn>
        ClientRouter& on(U8 type, Fn&& fn) {
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            _handlers[type] = [handler = std::move(handler)](const MsgView& msg) mutable -> Result {
                return detail::invoke_route_handler(handler, msg);
            };
            return *this;
        }

        template <class Fn>
        ClientRouter& on_text(U8 type, Fn&& fn) {
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            return on(type, [handler = std::move(handler)](const MsgView& msg) mutable -> Result {
                return detail::invoke_route_handler(handler, msg.text());
            });
        }

        template <class T, class Fn>
        ClientRouter& on_binary(U8 type, Fn&& fn) {
            static_assert(binary_message_type_supported_v<T>,
                          "ClientRouter::on_binary requires a trivially copyable, default constructible non-pointer type");
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            return on(type, [handler = std::move(handler)](const MsgView& msg) mutable -> Result {
                auto decoded = msg.as<T>();
                if (!decoded.ok()) {
                    return decoded.result();
                }
                return detail::invoke_route_handler(handler, decoded.value);
            });
        }

        template <class Fn>
        ClientRouter& on_unhandled(Fn&& fn) {
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            _fallback = [handler = std::move(handler)](const MsgView& msg) mutable -> Result {
                return detail::invoke_route_handler(handler, msg);
            };
            return *this;
        }

        ClientRouter& on_error(ErrorHandler fn) {
            _on_error = std::move(fn);
            return *this;
        }

        void clear(U8 type) { _handlers[type] = {}; }
        void clear() {
            for (auto& handler : _handlers) {
                handler = {};
            }
            _fallback = {};
            _on_error = {};
        }

        bool has(U8 type) const { return static_cast<bool>(_handlers[type]); }

        RouteResult dispatch(const MsgView& msg) {
            Handler& handler = _handlers[msg.type];
            if (handler) {
                const Result rc = handler(msg);
                if (!rc.ok() && _on_error) {
                    _on_error(msg, rc);
                }
                return { true, rc };
            }
            if (_fallback) {
                const Result rc = _fallback(msg);
                if (!rc.ok() && _on_error) {
                    _on_error(msg, rc);
                }
                return { true, rc };
            }
            return RouteResult::unhandled();
        }

        void attach(Client& client) {
            client.on_message([this](const MsgView& msg) {
                (void)dispatch(msg);
            });
        }

    private:
        std::array<Handler, 256> _handlers{};
        FallbackHandler _fallback{};
        ErrorHandler _on_error{};
    };

    class ServerRouter {
    public:
        using Handler = std::function<Result(Server::Peer, const MsgView&)>;
        using FallbackHandler = std::function<Result(Server::Peer, const MsgView&)>;
        using ErrorHandler = std::function<void(Server::Peer, const MsgView&, Result)>;

        ServerRouter() = default;

        template <class Fn>
        ServerRouter& on(U8 type, Fn&& fn) {
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            _handlers[type] = [handler = std::move(handler)](Server::Peer peer, const MsgView& msg) mutable -> Result {
                return detail::invoke_route_handler(handler, peer, msg);
            };
            return *this;
        }

        template <class Fn>
        ServerRouter& on_text(U8 type, Fn&& fn) {
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            return on(type, [handler = std::move(handler)](Server::Peer peer, const MsgView& msg) mutable -> Result {
                return detail::invoke_route_handler(handler, peer, msg.text());
            });
        }

        template <class T, class Fn>
        ServerRouter& on_binary(U8 type, Fn&& fn) {
            static_assert(binary_message_type_supported_v<T>,
                          "ServerRouter::on_binary requires a trivially copyable, default constructible non-pointer type");
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            return on(type, [handler = std::move(handler)](Server::Peer peer, const MsgView& msg) mutable -> Result {
                auto decoded = msg.as<T>();
                if (!decoded.ok()) {
                    return decoded.result();
                }
                return detail::invoke_route_handler(handler, peer, decoded.value);
            });
        }

        template <class Fn>
        ServerRouter& on_unhandled(Fn&& fn) {
            auto handler = std::decay_t<Fn>(std::forward<Fn>(fn));
            _fallback = [handler = std::move(handler)](Server::Peer peer, const MsgView& msg) mutable -> Result {
                return detail::invoke_route_handler(handler, peer, msg);
            };
            return *this;
        }

        ServerRouter& on_error(ErrorHandler fn) {
            _on_error = std::move(fn);
            return *this;
        }

        void clear(U8 type) { _handlers[type] = {}; }
        void clear() {
            for (auto& handler : _handlers) {
                handler = {};
            }
            _fallback = {};
            _on_error = {};
        }

        bool has(U8 type) const { return static_cast<bool>(_handlers[type]); }

        RouteResult dispatch(Server::Peer peer, const MsgView& msg) {
            Handler& handler = _handlers[msg.type];
            if (handler) {
                const Result rc = handler(peer, msg);
                if (!rc.ok() && _on_error) {
                    _on_error(peer, msg, rc);
                }
                return { true, rc };
            }
            if (_fallback) {
                const Result rc = _fallback(peer, msg);
                if (!rc.ok() && _on_error) {
                    _on_error(peer, msg, rc);
                }
                return { true, rc };
            }
            return RouteResult::unhandled();
        }

        void attach(Server& server) {
            server.on_message([this](Server::Peer peer, const MsgView& msg) {
                (void)dispatch(peer, msg);
            });
        }

    private:
        std::array<Handler, 256> _handlers{};
        FallbackHandler _fallback{};
        ErrorHandler _on_error{};
    };

} // namespace scn
