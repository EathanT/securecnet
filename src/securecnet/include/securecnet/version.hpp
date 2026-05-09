#pragma once

#include <string_view>

#include "securecnet/config.hpp"

#define SECURECNET_VERSION_MAJOR 0
#define SECURECNET_VERSION_MINOR 3
#define SECURECNET_VERSION_PATCH 0

namespace scn {

    constexpr int version_major() { return SECURECNET_VERSION_MAJOR; }
    constexpr int version_minor() { return SECURECNET_VERSION_MINOR; }
    constexpr int version_patch() { return SECURECNET_VERSION_PATCH; }
    constexpr std::string_view version() { return "0.3.0"; }
    constexpr U16 wire_protocol_version() { return NetConfig::ProtocolVersion; }

} // namespace scn
