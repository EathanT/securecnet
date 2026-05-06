#pragma once

#include <array>

#include "securecnet/bytebuf.hpp"
#include "securecnet/config.hpp"
#include "securecnet/result.hpp"

namespace scn {

    enum class ConnectionState : U8 {
        Idle = 0,
        Handshaking = 1,
        Established = 2,
        Closing = 3,
        Closed = 4,
    };

    enum class HandshakeType : U8 {
        ClientHello = 1,
        Retry = 2,
        ServerHello = 3,
    };

    enum class CloseReason : U16 {
        Normal = 0,
        IdleTimeout = 1,
        EstablishTimeout = 2,
        UnsupportedVersion = 3,
        AuthenticationFailed = 4,
        ReplayDetected = 5,
        ProtocolError = 6,
        InvalidPacket = 7,
        UnknownConnection = 8,
        CookieExpired = 9,
        StateViolation = 10,
        InternalError = 11,
        RateLimited = 12,
        Backpressure = 13,
    };

    constexpr bool close_reason_valid(CloseReason reason) {
        switch (reason) {
        case CloseReason::Normal:
        case CloseReason::IdleTimeout:
        case CloseReason::EstablishTimeout:
        case CloseReason::UnsupportedVersion:
        case CloseReason::AuthenticationFailed:
        case CloseReason::ReplayDetected:
        case CloseReason::ProtocolError:
        case CloseReason::InvalidPacket:
        case CloseReason::UnknownConnection:
        case CloseReason::CookieExpired:
        case CloseReason::StateViolation:
        case CloseReason::InternalError:
        case CloseReason::RateLimited:
        case CloseReason::Backpressure:
            return true;
        }
        return false;
    }

    struct RetryToken {
        U64 issued_at_ms{ 0 };
        std::array<U8, NetConfig::RetryTokenMacBytes> mac{};
    };

    struct ResumptionToken {
        U64 issued_at_ms{ 0 };
        U64 expires_at_ms{ 0 };
        U64 ticket_id{ 0 };
        std::array<U8, NetConfig::ResumptionTokenMacBytes> mac{};
    };

    struct ClientHello {
        std::array<U8, NetConfig::KeyExchangePublicKeyBytes> client_public_key{};
        std::array<U8, NetConfig::ClientNonceBytes> client_nonce{};
        bool has_retry_token{ false };
        RetryToken retry_token{};
        bool has_resumption_token{ false };
        ResumptionToken resumption_token{};
    };

    struct ServerHello {
        U64 server_conn_id{ 0 };
        std::array<U8, NetConfig::KeyExchangePublicKeyBytes> server_public_key{};
        std::array<U8, NetConfig::ServerNonceBytes> server_nonce{};
        std::array<U8, NetConfig::TranscriptMacBytes> transcript_mac{};
        bool has_resumption_token{ false };
        ResumptionToken resumption_token{};
    };

    struct CloseFrame {
        CloseReason reason{ CloseReason::Normal };
    };

    class ReplayWindow {
    public:
        bool accept(U64 sequence) {
            if (!_initialized) {
                _initialized = true;
                _latest = sequence;
                _seen = 1ull;
                return true;
            }
            if (sequence > _latest) {
                const U64 delta = sequence - _latest;
                if (delta >= 64) {
                    _seen = 0ull;
                } else {
                    _seen <<= delta;
                }
                _seen |= 1ull;
                _latest = sequence;
                return true;
            }
            const U64 delta = _latest - sequence;
            if (delta >= 64) {
                return false;
            }
            const U64 mask = (1ull << delta);
            const bool duplicate = (_seen & mask) != 0;
            _seen |= mask;
            return !duplicate;
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

    inline Result write_retry_token(ByteWriter& w, const RetryToken& token) {
        Result rc = w.write_u64(token.issued_at_ms);
        if (!rc.ok()) return rc;
        return w.write_bytes(token.mac.data(), token.mac.size());
    }

    inline Result read_retry_token(ByteReader& r, RetryToken& token) {
        token = {};
        Result rc = r.read_u64(token.issued_at_ms);
        if (!rc.ok()) return rc;
        rc = r.read_bytes(token.mac.data(), token.mac.size());
        if (!rc.ok()) return rc;
        return Result::success();
    }

    inline Result write_resumption_token(ByteWriter& w, const ResumptionToken& token) {
        Result rc = w.write_u64(token.issued_at_ms);
        if (!rc.ok()) return rc;
        rc = w.write_u64(token.expires_at_ms);
        if (!rc.ok()) return rc;
        rc = w.write_u64(token.ticket_id);
        if (!rc.ok()) return rc;
        return w.write_bytes(token.mac.data(), token.mac.size());
    }

    inline Result read_resumption_token(ByteReader& r, ResumptionToken& token) {
        token = {};
        Result rc = r.read_u64(token.issued_at_ms);
        if (!rc.ok()) return rc;
        rc = r.read_u64(token.expires_at_ms);
        if (!rc.ok()) return rc;
        rc = r.read_u64(token.ticket_id);
        if (!rc.ok()) return rc;
        rc = r.read_bytes(token.mac.data(), token.mac.size());
        if (!rc.ok()) return rc;
        if (token.ticket_id == 0 || token.expires_at_ms <= token.issued_at_ms) {
            return Result::fail(Errc::BadPacket, "invalid resumption token");
        }
        return Result::success();
    }

    inline Result write_client_hello(ByteWriter& w, const ClientHello& hello) {
        Result rc = w.write_u8(static_cast<U8>(HandshakeType::ClientHello));
        if (!rc.ok()) return rc;
        rc = w.write_bytes(hello.client_public_key.data(), hello.client_public_key.size());
        if (!rc.ok()) return rc;
        rc = w.write_bytes(hello.client_nonce.data(), hello.client_nonce.size());
        if (!rc.ok()) return rc;
        rc = w.write_u8(hello.has_retry_token ? 1 : 0);
        if (!rc.ok()) return rc;
        if (hello.has_retry_token) {
            rc = write_retry_token(w, hello.retry_token);
            if (!rc.ok()) return rc;
        }
        rc = w.write_u8(hello.has_resumption_token ? 1 : 0);
        if (!rc.ok()) return rc;
        if (hello.has_resumption_token) {
            rc = write_resumption_token(w, hello.resumption_token);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_client_hello(ByteReader& r, ClientHello& hello) {
        hello = {};
        U8 type = 0;
        Result rc = r.read_u8(type);
        if (!rc.ok()) return rc;
        if (type != static_cast<U8>(HandshakeType::ClientHello)) {
            return Result::fail(Errc::BadPacket, "expected client hello");
        }
        rc = r.read_bytes(hello.client_public_key.data(), hello.client_public_key.size());
        if (!rc.ok()) return rc;
        rc = r.read_bytes(hello.client_nonce.data(), hello.client_nonce.size());
        if (!rc.ok()) return rc;
        U8 has_retry = 0;
        rc = r.read_u8(has_retry);
        if (!rc.ok()) return rc;
        if (has_retry > 1) {
            return Result::fail(Errc::BadPacket, "invalid retry token flag");
        }
        hello.has_retry_token = has_retry != 0;
        if (hello.has_retry_token) {
            rc = read_retry_token(r, hello.retry_token);
            if (!rc.ok()) return rc;
        }
        U8 has_resumption = 0;
        rc = r.read_u8(has_resumption);
        if (!rc.ok()) return rc;
        if (has_resumption > 1) {
            return Result::fail(Errc::BadPacket, "invalid resumption token flag");
        }
        hello.has_resumption_token = has_resumption != 0;
        if (hello.has_resumption_token) {
            rc = read_resumption_token(r, hello.resumption_token);
            if (!rc.ok()) return rc;
        }
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in client hello");
        }
        return Result::success();
    }

    inline Result write_retry(ByteWriter& w, const RetryToken& token) {
        Result rc = w.write_u8(static_cast<U8>(HandshakeType::Retry));
        if (!rc.ok()) return rc;
        return write_retry_token(w, token);
    }

    inline Result read_retry(ByteReader& r, RetryToken& token) {
        token = {};
        U8 type = 0;
        Result rc = r.read_u8(type);
        if (!rc.ok()) return rc;
        if (type != static_cast<U8>(HandshakeType::Retry)) {
            return Result::fail(Errc::BadPacket, "expected retry");
        }
        rc = read_retry_token(r, token);
        if (!rc.ok()) return rc;
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in retry");
        }
        return Result::success();
    }

    inline Result write_server_hello(ByteWriter& w, const ServerHello& hello) {
        Result rc = w.write_u8(static_cast<U8>(HandshakeType::ServerHello));
        if (!rc.ok()) return rc;
        rc = w.write_u64(hello.server_conn_id);
        if (!rc.ok()) return rc;
        rc = w.write_bytes(hello.server_public_key.data(), hello.server_public_key.size());
        if (!rc.ok()) return rc;
        rc = w.write_bytes(hello.server_nonce.data(), hello.server_nonce.size());
        if (!rc.ok()) return rc;
        rc = w.write_bytes(hello.transcript_mac.data(), hello.transcript_mac.size());
        if (!rc.ok()) return rc;
        rc = w.write_u8(hello.has_resumption_token ? 1 : 0);
        if (!rc.ok()) return rc;
        if (hello.has_resumption_token) {
            rc = write_resumption_token(w, hello.resumption_token);
            if (!rc.ok()) return rc;
        }
        return Result::success();
    }

    inline Result read_server_hello(ByteReader& r, ServerHello& hello) {
        hello = {};
        U8 type = 0;
        Result rc = r.read_u8(type);
        if (!rc.ok()) return rc;
        if (type != static_cast<U8>(HandshakeType::ServerHello)) {
            return Result::fail(Errc::BadPacket, "expected server hello");
        }
        rc = r.read_u64(hello.server_conn_id);
        if (!rc.ok()) return rc;
        rc = r.read_bytes(hello.server_public_key.data(), hello.server_public_key.size());
        if (!rc.ok()) return rc;
        rc = r.read_bytes(hello.server_nonce.data(), hello.server_nonce.size());
        if (!rc.ok()) return rc;
        rc = r.read_bytes(hello.transcript_mac.data(), hello.transcript_mac.size());
        if (!rc.ok()) return rc;
        U8 has_resumption = 0;
        rc = r.read_u8(has_resumption);
        if (!rc.ok()) return rc;
        if (has_resumption > 1) {
            return Result::fail(Errc::BadPacket, "invalid server hello resumption flag");
        }
        hello.has_resumption_token = has_resumption != 0;
        if (hello.has_resumption_token) {
            rc = read_resumption_token(r, hello.resumption_token);
            if (!rc.ok()) return rc;
        }
        if (hello.server_conn_id == 0) {
            return Result::fail(Errc::BadPacket, "server hello missing conn id");
        }
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in server hello");
        }
        return Result::success();
    }

    inline Result write_close_frame(ByteWriter& w, const CloseFrame& close) {
        if (!close_reason_valid(close.reason)) {
            return Result::fail(Errc::InvalidArg, "invalid close reason");
        }
        return w.write_u16(static_cast<U16>(close.reason));
    }

    inline Result read_close_frame(ByteReader& r, CloseFrame& close) {
        close = {};
        U16 raw_reason = 0;
        Result rc = r.read_u16(raw_reason);
        if (!rc.ok()) return rc;
        if (r.remaining() != 0) {
            return Result::fail(Errc::BadPacket, "extra bytes in close frame");
        }
        close.reason = static_cast<CloseReason>(raw_reason);
        if (!close_reason_valid(close.reason)) {
            return Result::fail(Errc::BadPacket, "invalid close reason");
        }
        return Result::success();
    }

} // namespace scn
