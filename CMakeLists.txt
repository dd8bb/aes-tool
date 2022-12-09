cmake_minimum_required(VERSION 3.17.3)
set(AES_TOOL_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${AES_TOOL_PATH}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${AES_TOOL_PATH}/lib")


include_directories("${AES_TOOL_PATH}/3rd_parties/argp/include/argp-standalone")

include("${AES_TOOL_PATH}/3rd_parties/argp/CMakeLists.txt")

project(aes-tool VERSION 0.0.0 LANGUAGES C)

add_executable(aes-tool "${AES_TOOL_PATH}/aes-tool.c")

target_link_libraries(aes-tool -L${AES_TOOL_PATH}/lib)
target_link_libraries(aes-tool argp-standalone)

target_sources(${PROJECT_NAME} PRIVATE 
        "${AES_TOOL_PATH}/aes-tool.c"
        "${AES_TOOL_PATH}/aes_const.h"
	    "${AES_TOOL_PATH}/aes_core.h"
		"${AES_TOOL_PATH}/aes_core.c"
        "${AES_TOOL_PATH}/aes_cipher.h"
        "${AES_TOOL_PATH}/aes_inv_cipher.h"
	)

