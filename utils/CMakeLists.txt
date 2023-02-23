cmake_minimum_required(VERSION 3.6)
project(utils_static)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/)

add_library(utils_static STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/AndroidProp.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/MapTools.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/MemoryTools.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/selinux.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/progress.cpp
        )
target_link_libraries(utils_static log)
