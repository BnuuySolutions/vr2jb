#ifndef UTILS_HPP
#define UTILS_HPP

#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <limits.h>
#elif defined(__linux__)
#include <unistd.h>
#include <limits.h>
#endif

namespace Utils {

inline std::filesystem::path get_executable_dir() {
#if defined(_WIN32)
    // 32768 is the NT path limit plus null terminator
    std::wstring buffer(32768, L'\0');
    DWORD len = GetModuleFileNameW(NULL, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (len > 0 && len < buffer.size()) {
        buffer.resize(len);
        return std::filesystem::path(buffer).parent_path();
    }
#elif defined(__linux__)
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        return std::filesystem::path(buffer).parent_path();
    }
#elif defined(__APPLE__)
    char buffer[PATH_MAX];
    uint32_t size = sizeof(buffer);
    if (_NSGetExecutablePath(buffer, &size) == 0) {
        std::error_code err;
        auto canonical_path = std::filesystem::canonical(buffer, err);
        if (!err) {
            return canonical_path.parent_path();
        }
    }
#endif

    return std::filesystem::current_path();
}

inline std::string get_executable_relative_path(const std::string& rel_path) {
    std::filesystem::path p(rel_path);
    if (p.is_absolute()) {
        return rel_path;
    }
    return (get_executable_dir() / p).lexically_normal().string();
}

} // namespace Utils

#endif // UTILS_HPP
