#include "securecnet/crypto.hpp"
#include "securecnet/fragmentation.hpp"
#include "securecnet/message.hpp"
#include "securecnet/protocol.hpp"
#include "securecnet/reliability.hpp"
#include "securecnet/udp_socket.hpp"

#include <array>
#include <cstdio>
#include <type_traits>

using namespace scn;

static int expect(bool cond, const char* msg) {
    if (!cond) {
        std::printf("  %s\n", msg);
        return 1;
    }
    return 0;
}

int test_validation_hardening() {
    int fails = 0;

    static_assert(!std::is_copy_constructible_v<UdpSocket>);
    static_assert(!std::is_copy_assignable_v<UdpSocket>);
    static_assert(std::is_move_constructible_v<UdpSocket>);
    static_assert(std::is_move_assignable_v<UdpSocket>);

    {
        U8 bytes[8]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        CloseFrame close{};
        close.reason = static_cast<CloseReason>(999);
        auto rc = write_close_frame(writer, close);
        fails += expect(!rc.ok() && rc.code == Errc::InvalidArg,
                        "hardening: write_close_frame should reject unknown reasons");

        writer = ByteWriter{ bytes, sizeof(bytes) };
        rc = writer.write_u16(999);
        fails += expect(rc.ok(), "hardening: could not write raw invalid close reason");
        ByteReader reader{ bytes, writer.off };
        CloseFrame decoded{};
        rc = read_close_frame(reader, decoded);
        fails += expect(!rc.ok() && rc.code == Errc::BadPacket,
                        "hardening: read_close_frame should reject unknown reasons");
    }

    {
        U8 bytes[64]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = write_message(writer, static_cast<Channel>(99), 1, nullptr, 0);
        fails += expect(!rc.ok() && rc.code == Errc::InvalidArg,
                        "hardening: write_message should reject invalid channels");
    }

    {
        U8 bytes[64]{};
        ByteWriter writer{ bytes, sizeof(bytes) };
        auto rc = write_reliable_payload(writer, 0, nullptr, 0);
        fails += expect(!rc.ok() && rc.code == Errc::InvalidArg,
                        "hardening: reliable payload writer should reject id zero");

        writer = ByteWriter{ bytes, sizeof(bytes) };
        rc = writer.write_u64(0);
        fails += expect(rc.ok(), "hardening: could not write raw zero reliable id");
        ByteReader reader{ bytes, writer.off };
        ReliablePayloadView payload{};
        rc = read_reliable_payload(reader, payload);
        fails += expect(!rc.ok() && rc.code == Errc::BadPacket,
                        "hardening: reliable payload reader should reject id zero");

        writer = ByteWriter{ bytes, sizeof(bytes) };
        rc = write_reliable_ack(writer, Channel::Reliable, 0);
        fails += expect(!rc.ok() && rc.code == Errc::InvalidArg,
                        "hardening: ack writer should reject id zero");

        writer = ByteWriter{ bytes, sizeof(bytes) };
        rc = writer.write_u8(static_cast<U8>(Channel::Reliable));
        fails += expect(rc.ok(), "hardening: could not write raw ack channel");
        rc = writer.write_u64(0);
        fails += expect(rc.ok(), "hardening: could not write raw ack id");
        reader = ByteReader{ bytes, writer.off };
        Channel ack_channel = Channel::Reliable;
        U64 ack_id = 123;
        rc = read_reliable_ack(reader, ack_channel, ack_id);
        fails += expect(!rc.ok() && rc.code == Errc::BadPacket,
                        "hardening: ack reader should reject id zero");

        ReliableReceiveWindow window{};
        fails += expect(!window.accept(0), "hardening: receive window should reject id zero");
        fails += expect(!window.seen(0), "hardening: receive window should not report id zero as seen");
    }

    {
        U8 data[NetConfig::MaxFragmentDataBytes]{};
        U8 encoded[NetConfig::MaxMessageBytes]{};
        ByteWriter writer{ encoded, sizeof(encoded) };
        auto rc = write_fragment_payload(writer,
                                         1,
                                         0,
                                         static_cast<Channel>(99),
                                         7,
                                         0,
                                         1,
                                         1,
                                         data,
                                         1);
        fails += expect(!rc.ok() && rc.code == Errc::InvalidArg,
                        "hardening: fragment writer should reject invalid channel");

        FragmentationConfig cfg{};
        FragmentReassembler reassembler{};
        reassembler.configure(cfg);
        FragmentView bad{};
        bad.message_id = 1;
        bad.channel = Channel::Unreliable;
        bad.type = 7;
        bad.fragment_index = 3;
        bad.fragment_count = 1;
        bad.original_length = 1;
        bad.data = data;
        bad.len = 1;
        bool duplicate = false;
        bool completed = false;
        rc = reassembler.accept(1, bad,
                                [](const FragmentedMessage&) { return Result::success(); },
                                duplicate,
                                completed);
        fails += expect(!rc.ok() && rc.code == Errc::BadPacket,
                        "hardening: reassembler should reject invalid fragment index");
    }

    {
        std::array<U8, NetConfig::AeadKeyBytes> key{};
        std::array<U8, NetConfig::AeadNonceBytes> nonce{};
        std::array<U8, NetConfig::AeadTagBytes> ciphertext{};
        std::array<U8, NetConfig::AeadTagBytes> plaintext{};
        ST out_len = 0;
        auto rc = crypto_aead_encrypt(key.data(), key.size(),
                                      nonce.data(), nonce.size(),
                                      nullptr, 1,
                                      nullptr, 0,
                                      ciphertext.data(), ciphertext.size(), out_len);
        fails += expect(!rc.ok() && rc.code == Errc::InvalidArg,
                        "hardening: AEAD encrypt should reject null AAD with nonzero length");

        rc = crypto_aead_decrypt(key.data(), key.size(),
                                 nonce.data(), nonce.size(),
                                 nullptr, 1,
                                 ciphertext.data(), ciphertext.size(),
                                 plaintext.data(), plaintext.size(), out_len);
        fails += expect(!rc.ok() && rc.code == Errc::InvalidArg,
                        "hardening: AEAD decrypt should reject null AAD with nonzero length");
    }

    return fails;
}
