cmake_minimum_required(VERSION 3.0)

project(WoWOffsetDumper)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/macros")

include(AutoCollect)

add_subdirectory(src)