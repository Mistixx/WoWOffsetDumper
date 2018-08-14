CollectSourceFiles(
    ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE_SOURCES)

CollectIncludeDirectories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC_INCLUDES)

add_executable(WoWOffsetDumper
    ${PRIVATE_SOURCES})

target_include_directories(WoWOffsetDumper
    PUBLIC
        ${PUBLIC_INCLUDES}
		"${PROJECT_SOURCE_DIR}/deps/capstone/include/"
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(WoWOffsetDumper
    PUBLIC
        common
		capstone-static)

if (WIN32)
    install(TARGETS WoWOffsetDumper DESTINATION "${CMAKE_INSTALL_PREFIX}")
endif ()