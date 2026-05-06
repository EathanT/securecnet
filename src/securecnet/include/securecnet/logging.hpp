#pragma once

#include <functional>
#include <string_view>

namespace scn {

    enum class LogLevel {
        Error = 0,
        Warning = 1,
        Info = 2,
        Trace = 3,
        Debug = 4,
    };

    using LogFn = std::function<void(LogLevel, std::string_view)>;

} // namespace scn
