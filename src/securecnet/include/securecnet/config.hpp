#pragma once
#include <cstddef>
#include "securecnet/util/util.h"

namespace scn {

    struct NetConfig {
        // After IP/UDP + header/crypto overhead
        static constexpr ST MaxPacketBytes = 1300;
        static constexpr ST PacketHeaderBytes = 28;
        static constexpr ST MaxPayloadBytes = MaxPacketBytes - PacketHeaderBytes;

		// Message framing: [channel:1][type:1][len:2]
		static constexpr ST MessageHeaderBytes = 4;
        static constexpr ST MaxMessageBytes = MaxPayloadBytes - MessageHeaderBytes;

        // Reliable channel prepends message id
		static constexpr ST ReliableEnvelopeBytes = 8;
        static constexpr ST MaxReliableMessageBytes = MaxMessageBytes - ReliableEnvelopeBytes;
        static constexpr U64 ReliableResendDelayMs = 50;

        static constexpr U16 ProtocolVersion = 1;
        static constexpr U32 Magic = 0x53434E31; // "SCN1"
    };


	static_assert(NetConfig::MaxPacketBytes > NetConfig::PacketHeaderBytes, "MaxPacketBytes must be larger than PacketHeaderBytes");
	static_assert(NetConfig::MaxPayloadBytes > NetConfig::MessageHeaderBytes, "MaxPayloadBytes must be larger than MessageHeaderBytes");
	static_assert(NetConfig::MaxMessageBytes > NetConfig::ReliableEnvelopeBytes, "MaxMessageBytes must be larger than ReliableEnvelopeBytes");

}
