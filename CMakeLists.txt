cmake_minimum_required(VERSION 3.10)
project(vr2jb)

set(CMAKE_CXX_STANDARD 17)

set(BUILD_VR2BRIDGE ON)

set(VR2BRIDGE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vr2bridge")

execute_process(
    COMMAND docker build -t vr2bridge-builder "${VR2BRIDGE_DIR}"
    RESULT_VARIABLE DOCKER_BUILD_RESULT
)

if(NOT DOCKER_BUILD_RESULT EQUAL 0)
    message(STATUS "vr2bridge Docker image build failed. Will not build vr2bridge.")
    set(BUILD_VR2BRIDGE OFF)
endif()

if (BUILD_VR2BRIDGE)
    add_custom_target(vr2bridge_docker
        ALL
        
        COMMAND docker run --rm -v "${VR2BRIDGE_DIR}:/app" -v "${CMAKE_CURRENT_BINARY_DIR}:/app/out" vr2bridge-builder
        
        COMMENT "Building vr2bridge inside Docker container..."
        VERBATIM
    )
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(libusb REQUIRED IMPORTED_TARGET libusb-1.0)

add_executable(vr2jb
    main.cpp
    device.cpp
    rw.cpp
    logger.cpp
    bridge.cpp
    shell.cpp
    downgrade.cpp)

target_include_directories(vr2jb PUBLIC ${LIBUSB_INCLUDE_DIRS})
target_link_libraries(vr2jb PUBLIC PkgConfig::libusb)

target_compile_definitions(vr2jb PUBLIC NOMINMAX)