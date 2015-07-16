#ifndef COMMON_LOGGER_BACKEND_SYSLOG_HPP
#define COMMON_LOGGER_BACKEND_SYSLOG_HPP

#include "logger/backend.hpp"

namespace logger {

class SyslogBackend : public LogBackend {
public:
    void log(LogLevel logLevel,
             const std::string& file,
             const unsigned int& line,
             const std::string& func,
             const std::string& message) override;
};

} // namespace logger

#endif
