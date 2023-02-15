cmake_minimum_required(VERSION 3.4.1)

project(shark_inject C CXX)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie")
# set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../assets/shark_inject/${CMAKE_ANDROID_ARCH_ABI}/)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dlfcn)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/dlfcn)

add_library(inject2 SHARED inject2.cpp)
target_link_libraries(inject2 dlfcn_compat_static)

add_executable(shark_inject main.cpp shark_inject.c selinux.cc)

target_link_libraries(shark_inject log)

include_directories(frida/frida-android-${CMAKE_ANDROID_ARCH_ABI}/include/)
link_directories(frida/frida-android-${CMAKE_ANDROID_ARCH_ABI}/lib)
add_subdirectory(frida-inject-custom)
