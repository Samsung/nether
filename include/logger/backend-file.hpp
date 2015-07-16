#ifndef COMMON_LOGGER_BACKEND_FILE_HPP
#define COMMON_LOGGER_BACKEND_FILE_HPP

#include "logger/backend.hpp"

namespace logger {

class FileBackend : public LogBackend {
public:
    FileBackend(const std::string &_filePath) : filePath(_filePath) {}
    void log(LogLevel logLevel,
             const std::string& file,
             const unsigned int& line,
             const std::string& func,
             const std::string& message) override;
private:
    std::string filePath;
};

} // namespace logger

#endif
