cmake_minimum_required(VERSION 3.17.3)
set(AES_TOOL_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${AES_TOOL_PATH}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${AES_TOOL_PATH}/lib")

#Install argp library if needed
if (APPLE OR WIN32)
    message(STATUS "Not linux system, installing argp...")

    include("${AES_TOOL_PATH}/argp/CMakeLists.txt")
else()
	#cmake LINUX symbol is bugged and doesn't work
	#so we set a variable to use it instead
	set(LINUX_SYS 1)
endif()
#----

project(aes-tool VERSION 0.0.0 LANGUAGES C)

set(AES_TOOL_SRC_PATH "${AES_TOOL_PATH}/src")

include("${AES_TOOL_SRC_PATH}/CMakeLists.txt")

