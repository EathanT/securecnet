#pragma once
#include "securecnet/result.hpp"
#include "securecnet/endpoint.hpp"
#include <vector>
#include <string_view>

namespace scn {

    // Resolves host:port to endpoints
    Result resolve_endpoints(std::string_view host,
                             std::string_view port,
                             bool passive,
                             std::vector<Endpoint>& out);

}