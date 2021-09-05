cmake_minimum_required(VERSION 3.10)
project("pei"
        VERSION 1.2.0
        LANGUAGES C)

### Target architecture ###

if (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    set(ARCH "x86_64")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86|i386|i686")
    set(ARCH "i386")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "IA64|ia64")
    set(ARCH "ia64")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64|aarch64_be|armv8b|armv8l|ARM64")
    set(ARCH "arm64")
else()
    set(ARCH ${CMAKE_HOST_SYSTEM_PROCESSOR})
endif()

message("-- Target platform: ${ARCH}")

### Project's configurations ###

include("configuration.cmake")

if (UNIX)
    add_compile_definitions(ANSI_COLORS)
endif()


### Build configurations ###

function (find_src directory var)
    list(TRANSFORM SRCGLOB PREPEND "${directory}/" OUTPUT_VARIABLE GLOBLIST)
    file(GLOB SRCLIST RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS ${GLOBLIST})
    set(${var} ${SRCLIST} PARENT_SCOPE)
endfunction()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "bin")
include_directories(${INCDIRS})

find_src("src" ROOT_SRC)

# Architecture dependent directory
if (EXISTS "src/arch/${ARCH}")
    find_src("src/arch/${ARCH}" ARCH_SRC)
    include_directories("src/arch/${ARCH}/include")
endif()

# Subdirectories of src/ directory
foreach(SUBDIR ${SRCDIRS})
    find_src("src/${SUBDIR}" SUBDIR_SRC)
    list(APPEND SUBDIRECTORIES_SRC ${SUBDIR_SRC})
endforeach()


add_executable(${BINARY} ${ROOT_SRC} ${ARCH_SRC} ${SUBDIRECTORIES_SRC})
install(TARGETS ${BINARY})

include("tests.cmake")
