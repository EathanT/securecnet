#pragma once
#include <cstddef>
<<<<<<< HEAD
#include <securecnet/util/util.h>
=======
#include <util/util.h>
>>>>>>> origin/main

namespace scn {

    struct NetConfig {
        // After IP/UDP + header/crypto overhead 
        static constexpr ST MaxPacketBytes = 1300;

        static constexpr U16 ProtocolVersion = 1;
        static constexpr U32 Magic = 0x53434E31; // "SCN1"
    };

} 