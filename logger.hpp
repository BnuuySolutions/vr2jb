#pragma once

#include <iostream>
#include <sstream>

enum class LogLevel { L_DEBUG, L_INFO, L_WARNING, L_ERROR };

class Logger {
   public:
    static LogLevel current_level;
    static void set_level(LogLevel level);
    static LogLevel get_level();
};

class LogMessage {
   public:
    LogMessage(LogLevel level);
    ~LogMessage();

    template <typename T>
    LogMessage& operator<<(const T& value) {
        if (level >= Logger::current_level) {
            stream << value;
        }
        return *this;
    }

    typedef std::ostream& (*OstreamManipulator)(std::ostream&);
    LogMessage& operator<<(OstreamManipulator manip);

    typedef std::ios_base& (*IosBaseManipulator)(std::ios_base&);
    LogMessage& operator<<(IosBaseManipulator manip);

   private:
    LogLevel level;
    std::ostringstream stream;
};

#define LOG_DEBUG LogMessage(LogLevel::L_DEBUG)
#define LOG_INFO LogMessage(LogLevel::L_INFO)
#define LOG_WARN LogMessage(LogLevel::L_WARNING)
#define LOG_ERROR LogMessage(LogLevel::L_ERROR)