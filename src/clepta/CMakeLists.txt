add_library(clepta INTERFACE)

target_include_directories(clepta
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR})
		
target_link_libraries(clepta
	INTERFACE
		capstone-static)

target_compile_options(clepta
	INTERFACE
		/std:c++latest)