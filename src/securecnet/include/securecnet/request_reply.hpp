#pragma once

#include <chrono>
#include <future>
#include <limits>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "securecnet/client.hpp"
#include "securecnet/codec.hpp"
#include "securecnet/message.hpp"
#include "securecnet/router.hpp"
#include "securecnet/server.hpp"

namespace scn {

    static constexpr U8 RequestReplyDefaultMessageType = 250;
    static constexpr ST RequestReplyHeaderBytes = 13; // version + kind + id + app type + payload length.

    enum class RequestReplyKind : U8 {
        Request = 1,
        Response = 2,
        Error = 3,
    };

    struct RequestReplyFrame {
        RequestReplyKind kind{ RequestReplyKind::Request };
        U64 request_id{ 0 };
        U8 type{ 0 };
        const U8* data{ nullptr };
        U16 len{ 0 };

        std::span<const U8> bytes() const {
            if (!data || len == 0) {
                return {};
            }
            return std::span<const U8>(data, len);
        }

        std::string_view text() const {
            if (!data || len == 0) {
                return {};
            }
            return std::string_view(reinterpret_cast<const char*>(data), len);
        }
    };

    struct RequestReplyOptions {
        U8 envelope_type{ RequestReplyDefaultMessageType };
        SendOptions request_send{ Channel::ReliableOrdered, SendPriority::Normal, 0 };
        SendOptions response_send{ Channel::ReliableOrdered, SendPriority::Normal, 0 };
    };

    inline U64 steady_millis() {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<U64>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
    }

    inline bool request_reply_kind_valid(RequestReplyKind kind) {
        return kind == RequestReplyKind::Request ||
               kind == RequestReplyKind::Response ||
               kind == RequestReplyKind::Error;
    }

    inline ResultT<std::vector<U8>> make_request_reply_frame(RequestReplyKind kind,
                                                             U64 request_id,
                                                             U8 type,
                                                             std::span<const U8> payload) {
        if (!request_reply_kind_valid(kind)) {
            return ResultT<std::vector<U8>>::fail(Errc::InvalidArg, "invalid request/reply frame kind");
        }
        if (request_id == 0) {
            return ResultT<std::vector<U8>>::fail(Errc::InvalidArg, "request/reply id zero is reserved");
        }
        if (payload.size() > static_cast<ST>((std::numeric_limits<U16>::max)())) {
            return ResultT<std::vector<U8>>::fail(Errc::TooLarge, "request/reply payload too large");
        }
        if (!payload.empty() && payload.data() == nullptr) {
            return ResultT<std::vector<U8>>::fail(Errc::InvalidArg, "request/reply payload is null");
        }

        std::vector<U8> out(RequestReplyHeaderBytes + payload.size());
        ByteWriter writer(out.data(), out.size());
        auto rc = writer.write_u8(1); // frame version
        if (rc.ok()) rc = writer.write_u8(static_cast<U8>(kind));
        if (rc.ok()) rc = writer.write_u64(request_id);
        if (rc.ok()) rc = writer.write_u8(type);
        if (rc.ok()) rc = writer.write_u16(static_cast<U16>(payload.size()));
        if (rc.ok() && !payload.empty()) rc = writer.write_bytes(payload.data(), payload.size());
        if (!rc.ok()) {
            return ResultT<std::vector<U8>>::fail(rc.code, rc.msg);
        }
        return ResultT<std::vector<U8>>::success(std::move(out));
    }

    inline Result read_request_reply_frame(std::span<const U8> bytes, RequestReplyFrame& out) {
        out = {};
        if (bytes.size() < RequestReplyHeaderBytes) {
            return Result::fail(Errc::BadPacket, "truncated request/reply frame");
        }

        ByteReader reader(bytes.data(), bytes.size());
        U8 version{};
        U8 raw_kind{};
        U64 request_id{};
        U8 type{};
        U16 len{};
        auto rc = reader.read_u8(version);
        if (rc.ok()) rc = reader.read_u8(raw_kind);
        if (rc.ok()) rc = reader.read_u64(request_id);
        if (rc.ok()) rc = reader.read_u8(type);
        if (rc.ok()) rc = reader.read_u16(len);
        if (!rc.ok()) {
            return rc;
        }
        if (version != 1) {
            return Result::fail(Errc::UnsupportedVersion, "unsupported request/reply frame version");
        }
        const auto kind = static_cast<RequestReplyKind>(raw_kind);
        if (!request_reply_kind_valid(kind)) {
            return Result::fail(Errc::BadPacket, "invalid request/reply frame kind");
        }
        if (request_id == 0) {
            return Result::fail(Errc::BadPacket, "request/reply id zero is invalid");
        }
        if (len != reader.remaining()) {
            return Result::fail(Errc::BadPacket, "request/reply payload length mismatch");
        }

        out.kind = kind;
        out.request_id = request_id;
        out.type = type;
        out.len = len;
        out.data = len == 0 ? nullptr : reader.peek_ptr(len);
        return Result::success();
    }

    inline Result read_request_reply_frame(const MsgView& msg,
                                           RequestReplyFrame& out,
                                           U8 envelope_type = RequestReplyDefaultMessageType) {
        if (msg.type != envelope_type) {
            return Result::fail(Errc::ProtocolError, "message is not a request/reply envelope");
        }
        return read_request_reply_frame(msg.bytes(), out);
    }

    inline Result send_request(Client& client,
                               U64 request_id,
                               U8 type,
                               std::span<const U8> payload,
                               const RequestReplyOptions& options = {}) {
        auto frame = make_request_reply_frame(RequestReplyKind::Request, request_id, type, payload);
        if (!frame.ok()) {
            return frame.result();
        }
        return client.send(options.request_send, options.envelope_type, frame.value);
    }

    inline Result send_response(const Server::Peer& peer,
                                const RequestReplyFrame& request,
                                std::span<const U8> payload,
                                const RequestReplyOptions& options = {}) {
        if (request.kind != RequestReplyKind::Request) {
            return Result::fail(Errc::InvalidArg, "response requires a request frame");
        }
        auto frame = make_request_reply_frame(RequestReplyKind::Response, request.request_id, request.type, payload);
        if (!frame.ok()) {
            return frame.result();
        }
        return peer.send(options.response_send, options.envelope_type, frame.value);
    }

    inline Result send_error_response(const Server::Peer& peer,
                                      const RequestReplyFrame& request,
                                      std::string_view error,
                                      const RequestReplyOptions& options = {}) {
        if (request.kind != RequestReplyKind::Request) {
            return Result::fail(Errc::InvalidArg, "error response requires a request frame");
        }
        auto payload = std::span<const U8>(reinterpret_cast<const U8*>(error.data()), error.size());
        auto frame = make_request_reply_frame(RequestReplyKind::Error, request.request_id, request.type, payload);
        if (!frame.ok()) {
            return frame.result();
        }
        return peer.send(options.response_send, options.envelope_type, frame.value);
    }

    class RequestIdSource {
    public:
        U64 next() {
            U64 value = _next++;
            if (value == 0) {
                value = _next++;
            }
            return value;
        }

        void reset(U64 first = 1) {
            _next = first == 0 ? 1 : first;
        }

    private:
        U64 _next{ 1 };
    };

    class ClientRequestTable {
    public:
        explicit ClientRequestTable(RequestReplyOptions options = {}) : _options(options) {}

        const RequestReplyOptions& options() const { return _options; }
        ST pending_count() const { return _pending.size(); }

        ResultT<std::future<ResultT<std::vector<U8>>>> request(Client& client,
                                                               U8 type,
                                                               std::span<const U8> payload,
                                                               U64 timeout_ms = 5000) {
            const U64 id = _ids.next();
            auto frame = make_request_reply_frame(RequestReplyKind::Request, id, type, payload);
            if (!frame.ok()) {
                return ResultT<std::future<ResultT<std::vector<U8>>>>::fail(frame.code, frame.msg);
            }

            std::promise<ResultT<std::vector<U8>>> promise;
            auto future = promise.get_future();
            Pending pending{};
            pending.promise = std::move(promise);
            pending.expires_at_ms = timeout_ms == 0 ? 0 : steady_millis() + timeout_ms;
            _pending.emplace(id, std::move(pending));

            auto rc = client.send(_options.request_send, _options.envelope_type, frame.value);
            if (!rc.ok()) {
                auto it = _pending.find(id);
                if (it != _pending.end()) {
                    it->second.promise.set_value(ResultT<std::vector<U8>>::fail(rc.code, rc.msg));
                    _pending.erase(it);
                }
                return ResultT<std::future<ResultT<std::vector<U8>>>>::fail(rc.code, rc.msg);
            }

            return ResultT<std::future<ResultT<std::vector<U8>>>>::success(std::move(future));
        }

        RouteResult dispatch(const MsgView& msg) {
            if (msg.type != _options.envelope_type) {
                return RouteResult::unhandled();
            }
            RequestReplyFrame frame{};
            auto rc = read_request_reply_frame(msg, frame, _options.envelope_type);
            if (!rc.ok()) {
                return { true, rc };
            }
            if (frame.kind != RequestReplyKind::Response && frame.kind != RequestReplyKind::Error) {
                return RouteResult::unhandled();
            }
            auto it = _pending.find(frame.request_id);
            if (it == _pending.end()) {
                return RouteResult::fail(Errc::ProtocolError, "response for unknown request id");
            }

            if (frame.kind == RequestReplyKind::Error) {
                it->second.promise.set_value(ResultT<std::vector<U8>>::fail(Errc::ProtocolError, "remote request error"));
            } else {
                it->second.promise.set_value(ResultT<std::vector<U8>>::success(std::vector<U8>(frame.bytes().begin(), frame.bytes().end())));
            }
            _pending.erase(it);
            return RouteResult::success();
        }

        ST expire(U64 now_ms = steady_millis()) {
            ST expired = 0;
            for (auto it = _pending.begin(); it != _pending.end();) {
                if (it->second.expires_at_ms != 0 && now_ms >= it->second.expires_at_ms) {
                    it->second.promise.set_value(ResultT<std::vector<U8>>::fail(Errc::Timeout, "request timed out"));
                    it = _pending.erase(it);
                    ++expired;
                } else {
                    ++it;
                }
            }
            return expired;
        }

        void cancel_all(Errc code = Errc::Closed, std::string_view msg = "request table closed") {
            for (auto& entry : _pending) {
                entry.second.promise.set_value(ResultT<std::vector<U8>>::fail(code, msg));
            }
            _pending.clear();
        }

    private:
        struct Pending {
            std::promise<ResultT<std::vector<U8>>> promise{};
            U64 expires_at_ms{ 0 };
        };

        RequestReplyOptions _options{};
        RequestIdSource _ids{};
        std::unordered_map<U64, Pending> _pending{};
    };

} // namespace scn
