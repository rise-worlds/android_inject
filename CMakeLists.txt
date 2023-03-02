cmake_minimum_required(VERSION 3.4.1)

project(shark_inject C CXX)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-DANDROID)
set(VCPKG_CMAKE_SYSTEM_NAME Android)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -fPIE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections -fPIE")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs,ALL, -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie -Wl,-z,relro,-z,noexecstack,--gc-sections")
# set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../assets/shark_inject/${CMAKE_ANDROID_ARCH_ABI}/)

if (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    set(VCPKG_TARGET_TRIPLET arm64-android)
    include($ENV{VCPKG_ROOT}/triplets/community/arm64-android.cmake)
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=softfp -mfpu=vfpv3-d16")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=softfp -mfpu=vfpv3-d16")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--fix-cortex-a8")
    set(VCPKG_TARGET_TRIPLET arm-android)
    include($ENV{VCPKG_ROOT}/triplets/community/arm-android.cmake)
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
    set(VCPKG_TARGET_TRIPLET x64-android)
    include($ENV{VCPKG_ROOT}/triplets/community/x64-android.cmake)
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpmath=sse -mstackrealign")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpmath=sse -mstackrealign")
    set(VCPKG_TARGET_TRIPLET x86-android)
    include($ENV{VCPKG_ROOT}/triplets/community/x86-android.cmake)
endif()

add_definitions(
    -DFMT_HEADER_ONLY
    -DSPDLOG_FMT_EXTERNAL
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/
    ${CMAKE_CURRENT_SOURCE_DIR}/asio
    ${CMAKE_CURRENT_SOURCE_DIR}/fmt/include
    ${CMAKE_CURRENT_SOURCE_DIR}/spdlog/include
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib/contrib/minizip
)

set(DOBBY_GENERATE_SHARED OFF)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dobby)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/fmt)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/spdlog)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/nlohmann_json)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/zlib)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/dobby/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Il2cppResolver
    ${CMAKE_CURRENT_SOURCE_DIR}/dlfcn
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    )
    
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/utils)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dlfcn)

add_library(inject2 SHARED inject2.cpp)
target_link_libraries(inject2 dlfcn_compat_static)

add_executable(shark_inject main.cc shark_inject.c)
target_link_libraries(shark_inject utils_static)

include_directories(frida/frida-android-${CMAKE_ANDROID_ARCH_ABI}/include/)
link_directories(frida/frida-android-${CMAKE_ANDROID_ARCH_ABI}/lib)
add_subdirectory(frida-inject-custom)

add_library(UnityCheat SHARED UnityCheat.cpp)
target_link_libraries(UnityCheat dobby frida-gum utils_static)
set_target_properties(UnityCheat PROPERTIES LINK_FLAGS "-Wl,--gc-sections,-s,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/UnityCheat.version")

add_library(UnityCheat2 SHARED UnityCheat2.cpp)
target_link_libraries(UnityCheat2 frida-gum utils_static)
set_target_properties(UnityCheat2 PROPERTIES LINK_FLAGS "-Wl,--gc-sections,-s,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/UnityCheat.version")

add_executable(CheckUnity CheckUnity.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib/contrib/minizip/unzip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib/contrib/minizip/ioapi.c
    )
target_include_directories(CheckUnity PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/zlib)
add_dependencies(${PROJECT_NAME} zlibstatic)
target_link_libraries(CheckUnity zlibstatic)
