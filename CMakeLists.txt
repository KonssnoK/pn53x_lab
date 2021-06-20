
cmake_minimum_required(VERSION 3.0)
project(pn53x_lab)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Readline)

message("Readline found: ${Readline_FOUND}")

set(LIBNFC_SOURCES "/home/bartezza/nfc/libnfc" CACHE PATH "libnfc sources base path")

include_directories(
    ${LIBNFC_SOURCES}
    ${LIBNFC_SOURCES}/libnfc
    ${Readline_INCLUDE_DIR}
)

if (Readline_FOUND)
    add_definitions("-DHAVE_READLINE")
endif()

set(SRCS
    pn53x_lab.cpp
    ${LIBNFC_SOURCES}/utils/nfc-utils.c
)

set(TARGET pn53x_lab)

add_executable(${TARGET} ${SRCS})
target_link_libraries(${TARGET} nfc ${Readline_LIBRARY})
