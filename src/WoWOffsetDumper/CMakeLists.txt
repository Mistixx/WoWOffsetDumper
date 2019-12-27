CollectSourceFiles(
    ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE_SOURCES)

add_executable(WoWOffsetDumper
    ${PRIVATE_SOURCES})

target_include_directories(WoWOffsetDumper
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
		"${PROJECT_SOURCE_DIR}/deps/capstone/include/")

target_link_libraries(WoWOffsetDumper
	PRIVATE
		capstone-static
		clepta)

if (WIN32)
    install(TARGETS WoWOffsetDumper DESTINATION "${CMAKE_INSTALL_PREFIX}")
endif ()