#include "logger.hpp"

LogLevel Logger::current_level = LogLevel::L_INFO;

void Logger::set_level(LogLevel level) { current_level = level; }

LogLevel Logger::get_level() { return current_level; }

LogMessage::LogMessage(LogLevel level) : level(level) {}

LogMessage::~LogMessage() {
    if (level >= Logger::current_level) {
        if (level == LogLevel::L_ERROR) {
            std::cerr << stream.str();
        } else {
            std::cout << stream.str();
        }
    }
}

LogMessage& LogMessage::operator<<(OstreamManipulator manip) {
    if (level >= Logger::current_level) {
        manip(stream);
    }
    return *this;
}

LogMessage& LogMessage::operator<<(IosBaseManipulator manip) {
    if (level >= Logger::current_level) {
        manip(stream);
    }
    return *this;
}