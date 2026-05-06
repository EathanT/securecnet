#include "securecnet/bytebuf.hpp"
#include "securecnet/protocol.hpp"

#include <cstdio>
#include <cstring>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

static void fill_bytes(U8* dst, ST len, U8 seed) {
    for (ST i = 0; i < len; ++i) {
        dst[i] = static_cast<U8>((static_cast<U32>(seed) + static_cast<U32>(i * 7u)) & 0xFFu);
    }
}

int test_protocol() {
    int fails = 0;

    {
        ClientHello hello{};
        fill_bytes(hello.client_public_key.data(), hello.client_public_key.size(), 3);
        fill_bytes(hello.client_nonce.data(), hello.client_nonce.size(), 19);
        hello.has_retry_token = true;
        hello.retry_token.issued_at_ms = 1234;
        fill_bytes(hello.retry_token.mac.data(), hello.retry_token.mac.size(), 33);

        U8 bytes[256]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = write_client_hello(writer, hello);
        fails += expect(rc.ok(), "protocol: write_client_hello failed");

        ByteReader reader{ bytes, writer.off };
        ClientHello decoded{};
        rc = read_client_hello(reader, decoded);
        fails += expect(rc.ok(), "protocol: read_client_hello failed");
        fails += expect(decoded.has_retry_token, "protocol: decoded client hello should include retry token");
        fails += expect(!decoded.has_resumption_token, "protocol: decoded client hello should not include resumption token");
        fails += expect(decoded.retry_token.issued_at_ms == 1234, "protocol: retry token issue time mismatch");
        fails += expect(std::memcmp(decoded.client_public_key.data(), hello.client_public_key.data(), hello.client_public_key.size()) == 0,
                        "protocol: client public key mismatch");
    }

    {
        ResumptionToken token{};
        token.issued_at_ms = 10;
        token.expires_at_ms = 1000;
        token.ticket_id = 77;
        fill_bytes(token.mac.data(), token.mac.size(), 5);

        ServerHello hello{};
        hello.server_conn_id = 44;
        fill_bytes(hello.server_public_key.data(), hello.server_public_key.size(), 11);
        fill_bytes(hello.server_nonce.data(), hello.server_nonce.size(), 29);
        fill_bytes(hello.transcript_mac.data(), hello.transcript_mac.size(), 41);
        hello.has_resumption_token = true;
        hello.resumption_token = token;

        U8 bytes[256]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = write_server_hello(writer, hello);
        fails += expect(rc.ok(), "protocol: write_server_hello failed");

        ByteReader reader{ bytes, writer.off };
        ServerHello decoded{};
        rc = read_server_hello(reader, decoded);
        fails += expect(rc.ok(), "protocol: read_server_hello failed");
        fails += expect(decoded.server_conn_id == 44, "protocol: server hello conn id mismatch");
        fails += expect(decoded.has_resumption_token, "protocol: server hello missing resumption token");
        fails += expect(decoded.resumption_token.ticket_id == token.ticket_id,
                        "protocol: server hello resumption token mismatch");
    }

    {
        ResumptionToken token{};
        token.issued_at_ms = 100;
        token.expires_at_ms = 100;
        token.ticket_id = 55;
        fill_bytes(token.mac.data(), token.mac.size(), 17);

        U8 bytes[64]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = writer.write_u64(token.issued_at_ms);
        fails += expect(rc.ok(), "protocol: write issued_at failed");
        rc = writer.write_u64(token.expires_at_ms);
        fails += expect(rc.ok(), "protocol: write expires_at failed");
        rc = writer.write_u64(token.ticket_id);
        fails += expect(rc.ok(), "protocol: write ticket_id failed");
        rc = writer.write_bytes(token.mac.data(), token.mac.size());
        fails += expect(rc.ok(), "protocol: write resumption mac failed");

        ByteReader reader{ bytes, writer.off };
        ResumptionToken decoded{};
        rc = read_resumption_token(reader, decoded);
        fails += expect(!rc.ok() && rc.code == Errc::BadPacket,
                        "protocol: invalid resumption token should be rejected");
    }

    {
        CloseFrame close{};
        close.reason = CloseReason::Backpressure;
        U8 bytes[16]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = write_close_frame(writer, close);
        fails += expect(rc.ok(), "protocol: write_close_frame failed");

        ByteReader reader{ bytes, writer.off };
        CloseFrame decoded{};
        rc = read_close_frame(reader, decoded);
        fails += expect(rc.ok(), "protocol: read_close_frame failed");
        fails += expect(decoded.reason == CloseReason::Backpressure, "protocol: close reason mismatch");
    }

    {
        ClientHello hello{};
        fill_bytes(hello.client_public_key.data(), hello.client_public_key.size(), 9);
        fill_bytes(hello.client_nonce.data(), hello.client_nonce.size(), 13);

        U8 bytes[256]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = write_client_hello(writer, hello);
        fails += expect(rc.ok(), "protocol: write bare client hello failed");
        bytes[1 + NetConfig::KeyExchangePublicKeyBytes + NetConfig::ClientNonceBytes] = 2;

        ByteReader reader{ bytes, writer.off };
        ClientHello decoded{};
        rc = read_client_hello(reader, decoded);
        fails += expect(!rc.ok() && rc.code == Errc::BadPacket,
                        "protocol: invalid retry-token flag should be rejected");
    }

    return fails;
}
