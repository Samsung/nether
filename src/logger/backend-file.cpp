#include "logger/config.hpp"
#include "logger/formatter.hpp"
#include "logger/backend-file.hpp"

#include <fstream>

namespace logger {

void FileBackend::log(LogLevel logLevel,
                                const std::string& file,
                                const unsigned int& line,
                                const std::string& func,
                                const std::string& message)
{
    std::ofstream out(filePath, std::ios::app);
    out << LogFormatter::getHeader(logLevel, file, line, func);
    out << message;
    out << "\n";
}


}
