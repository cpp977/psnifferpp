cmake_minimum_required(VERSION 3.22)
project(socket_tests LANGUAGES CXX)

find_package(sockpp REQUIRED)
find_package(flags REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(socket_tests sock.cpp)

target_compile_options(socket_tests PRIVATE "-Wall" "-Wpedantic" "-Wextra" "-Wconversion")
target_link_libraries(socket_tests Sockpp::sockpp flags::flags)
