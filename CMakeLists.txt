cmake_minimum_required(VERSION 3.0)

project(WoWOffsetDumper)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/macros")

include(AutoCollect)

set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Build shared library")
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Build tests")
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Build cstool")

add_subdirectory(deps)
add_subdirectory(src)