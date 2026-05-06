#include "securecnet/address.hpp"
#include "securecnet/nat.hpp"
#include "securecnet/stream.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_nat_stream() {
    int fails = 0;

    {
        std::vector<Endpoint> endpoints{};
        auto rc = resolve_endpoints("127.0.0.1", "27015", false, endpoints);
        fails += expect(rc.ok() && !endpoints.empty(), "nat_stream: resolve_endpoints failed");
        if (rc.ok() && !endpoints.empty()) {
            NatPeerHint hint{};
            rc = make_nat_peer_hint(endpoints.front(), hint);
            fails += expect(rc.ok(), "nat_stream: make_nat_peer_hint failed");
            fails += expect(hint.family == NatHintFamily::IPv4, "nat_stream: expected IPv4 hint family");
            fails += expect(hint.port == 27015, "nat_stream: nat hint port mismatch");

            U8 bytes[32]{};
            ByteWriter writer{ bytes, sizeof(bytes) };
            rc = write_nat_peer_hint(writer, hint);
            fails += expect(rc.ok(), "nat_stream: write_nat_peer_hint failed");

            ByteReader reader{ bytes, writer.off };
            NatPeerHint decoded{};
            rc = read_nat_peer_hint(reader, decoded);
            fails += expect(rc.ok(), "nat_stream: read_nat_peer_hint failed");
            fails += expect(decoded.port == hint.port, "nat_stream: decoded nat hint port mismatch");

            Endpoint round_trip{};
            rc = endpoint_from_nat_peer_hint(decoded, round_trip);
            fails += expect(rc.ok(), "nat_stream: endpoint_from_nat_peer_hint failed");
            fails += expect(round_trip.port() == endpoints.front().port(), "nat_stream: endpoint port round-trip mismatch");
        }
    }

    {
        NatPunchFrame punch{};
        punch.token = 0xABCDEF;
        punch.issued_at_ms = 12345;
        U8 bytes[32]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = write_nat_punch_frame(writer, punch);
        fails += expect(rc.ok(), "nat_stream: write_nat_punch_frame failed");

        ByteReader reader{ bytes, writer.off };
        NatPunchFrame decoded{};
        rc = read_nat_punch_frame(reader, decoded);
        fails += expect(rc.ok(), "nat_stream: read_nat_punch_frame failed");
        fails += expect(decoded.token == punch.token && decoded.issued_at_ms == punch.issued_at_ms,
                        "nat_stream: nat punch frame mismatch");
    }

    {
        std::vector<U8> payload(max_stream_frame_payload() + 37);
        for (ST i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<U8>((i * 9u) & 0xFFu);
        }

        std::vector<std::vector<U8>> chunks{};
        auto rc = chunk_stream_bytes(7, std::span<const U8>(payload.data(), payload.size()),
                                     [&](std::span<const U8> chunk, bool) {
                                         chunks.emplace_back(chunk.begin(), chunk.end());
                                         return Result::success();
                                     });
        fails += expect(rc.ok(), "nat_stream: chunk_stream_bytes failed");
        fails += expect(chunks.size() == 2, "nat_stream: expected two stream chunks");

        StreamReceiveBuffer buffer{};
        for (ST i = 0; i < chunks.size(); ++i) {
            ByteReader reader{ chunks[i].data(), chunks[i].size() };
            StreamFrameView frame{};
            rc = read_stream_frame(reader, frame);
            fails += expect(rc.ok(), "nat_stream: read_stream_frame failed");
            rc = buffer.append(frame);
            fails += expect(rc.ok(), "nat_stream: StreamReceiveBuffer append failed");
        }
        fails += expect(buffer.finished(), "nat_stream: stream buffer should finish after final frame");
        fails += expect(buffer.stream_id() == 7, "nat_stream: stream id mismatch");
        auto assembled = buffer.bytes();
        fails += expect(assembled.size() == payload.size(), "nat_stream: assembled stream size mismatch");
        fails += expect(std::memcmp(assembled.data(), payload.data(), payload.size()) == 0,
                        "nat_stream: assembled stream payload mismatch");
    }

    return fails;
}
