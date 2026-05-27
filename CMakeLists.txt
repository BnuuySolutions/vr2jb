cmake_minimum_required(VERSION 3.10)
project(vr2jb_cpp)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libusb REQUIRED IMPORTED_TARGET libusb-1.0)

add_executable(vr2jb
    main.cpp
    device.cpp
    rw.cpp
    logger.cpp
    bridge.cpp
    shell.cpp)
target_include_directories(vr2jb PUBLIC ${LIBUSB_INCLUDE_DIRS})
target_link_libraries(vr2jb PUBLIC PkgConfig::libusb)

# NOMINMAX
target_compile_definitions(vr2jb PUBLIC NOMINMAX)