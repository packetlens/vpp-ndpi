cmake_minimum_required(VERSION 3.16)
project(vpp-ndpi)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(VPP REQUIRED)

find_package(PkgConfig)
if(PkgConfig_FOUND)
    pkg_check_modules(NDPI libndpi)
endif()

if(NOT NDPI_FOUND)
    find_path(NDPI_INCLUDE_DIR ndpi_api.h PATH_SUFFIXES ndpi)
    find_library(NDPI_LIBRARY NAMES ndpi)
    if(NDPI_INCLUDE_DIR AND NDPI_LIBRARY)
        set(NDPI_FOUND TRUE)
        set(NDPI_INCLUDE_DIRS ${NDPI_INCLUDE_DIR})
        set(NDPI_LIBRARIES ${NDPI_LIBRARY})
        message(STATUS "Found nDPI (manual): include=${NDPI_INCLUDE_DIR} lib=${NDPI_LIBRARY}")
    endif()
endif()

if(NOT NDPI_FOUND)
    message(FATAL_ERROR "nDPI (libndpi) not found. Install libndpi-dev.")
endif()

include_directories(${CMAKE_SOURCE_DIR}/src/plugins)
include_directories(${NDPI_INCLUDE_DIRS})
link_directories(${NDPI_LIBRARY_DIRS})

add_subdirectory(src/plugins/ndpi)
