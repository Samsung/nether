#include "logger/config.hpp"
#include "logger/formatter.hpp"
#include "logger/backend-syslog.hpp"

#include <syslog.h>
#include <sstream>
namespace logger {

namespace {

inline int toSyslogPriority(LogLevel logLevel)
{
    switch (logLevel) {
    case LogLevel::ERROR:
        return LOG_ERR;     // 3
    case LogLevel::WARN:
        return LOG_WARNING; // 4
    case LogLevel::INFO:
        return LOG_INFO;    // 6
    case LogLevel::DEBUG:
        return LOG_DEBUG;   // 7
    case LogLevel::TRACE:
        return LOG_DEBUG;   // 7
    case LogLevel::HELP:
        return LOG_DEBUG;   // 7
    default:
        return LOG_DEBUG;   // 7
    }
}

} // namespace

void SyslogBackend::log(LogLevel logLevel,
                                const std::string& file,
                                const unsigned int& line,
                                const std::string& func,
                                const std::string& message)
{
    syslog(toSyslogPriority(logLevel), "%s %s", LogFormatter::getHeader(logLevel, file, line, func).c_str(), message.c_str());
}

}
