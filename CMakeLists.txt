cmake_minimum_required(VERSION 3.4.1)

project(shark_inject C CXX)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -fPIE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections -fPIE")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs,ALL, -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie -Wl,-z,relro,-z,noexecstack,--gc-sections")
# set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../assets/shark_inject/${CMAKE_ANDROID_ARCH_ABI}/)

if (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=softfp -mfpu=vfpv3-d16")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=softfp -mfpu=vfpv3-d16")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--fix-cortex-a8")
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpmath=sse -mstackrealign")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpmath=sse -mstackrealign")
endif()

add_definitions(-DANDROID)

set(DOBBY_GENERATE_SHARED OFF)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dobby)

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
