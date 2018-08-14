CollectSourceFiles(
    ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE_SOURCES)

CollectIncludeDirectories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC_INCLUDES)

add_library(common
    ${PRIVATE_SOURCES})

target_include_directories(common
    PUBLIC
        ${PUBLIC_INCLUDES}
		"${PROJECT_SOURCE_DIR}/deps/capstone/include/"
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(common
    PUBLIC
		capstone-static)