


set(HEADERS
	"${AES_TOOL_SRC_PATH}/aes_const.h"
	"${AES_TOOL_SRC_PATH}/aes_core.h"
    "${AES_TOOL_SRC_PATH}/aes_context.h"
	"${AES_TOOL_SRC_PATH}/aes_cipher.h"
	"${AES_TOOL_SRC_PATH}/aes_inv_cipher.h"
	"${AES_TOOL_SRC_PATH}/aes_crypt.h"
	"${AES_TOOL_SRC_PATH}/base_64.h"
   )

set(SOURCES
    "${AES_TOOL_SRC_PATH}/aes-tool.c"
	"${AES_TOOL_SRC_PATH}/aes_core.c"
	"${AES_TOOL_SRC_PATH}/aes_context.c"
    "${AES_TOOL_SRC_PATH}/aes_crypt.c"
   )

add_executable(${PROJECT_NAME} "${AES_TOOL_SRC_PATH}/aes-tool.c")

if (APPLE OR WIN32)
    include_directories("${ARGP_BASE_PATH}/include/argp-standalone")
    target_link_libraries(${PROJECT_NAME} -L${AES_TOOL_PATH}/lib)
    target_link_libraries(${PROJECT_NAME} argp-standalone)
endif()

#Debug build options & definitions
if (CMAKE_BUILD_TYPE MATCHES "Debug")
    message(STATUS "Debug mode")
    target_compile_definitions(${PROJECT_NAME} PUBLIC AES_TOOL_DEBUG)
endif()

#Release options & definitions
if (CMAKE_BUILD_TYPE MATCHES "Release")
	message(STATUS "Release mode")
	set(CMAKE_INSTALL_CONFIG_NAME "Release")
endif()

if (APPLE OR LINUX_SYS)
    install(TARGETS ${PROJECT_NAME} CONFIGURATIONS Release)
endif()

target_sources(${PROJECT_NAME} PRIVATE ${HEADERS} ${SOURCES})
