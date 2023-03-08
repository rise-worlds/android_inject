cmake_minimum_required(VERSION 3.4.1)

project(shark_inject C CXX)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      add_compile_options(
          /bigobj       # large object file format
          #/permissive-  # strict C++
          #/wd4503      # decorated name length exceeded, name was truncated
          /W4           # enable all warnings
          /JMC
          )
  
      set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /std:c++17 /MTd")
      set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /std:c++17 /Zi /Ob2 /Oi /Ot /MT")
  
      set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")
    else()
      add_compile_options(
          /bigobj       # large object file format
          #/permissive-  # strict C++
          #/wd4503      # decorated name length exceeded, name was truncated
          /W4           # enable all warnings
          /MP           # Multi-processor compilation
          /JMC
          /Zc:__cplusplus
          )
  
      set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /std:c++17 /MTd /ZI")
      set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /std:c++17 /Zi /Ob2 /Oi /Ot /GL /MT")
  
      set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

      set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")
      set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG:incremental")
    endif ()
else()
    add_definitions(-DANDROID)
    set(VCPKG_CMAKE_SYSTEM_NAME Android)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -fPIE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections -fPIE")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs,ALL, -Wl,--gc-sections")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie -Wl,--exclude-libs,ALL, -Wl,-z,relro,-z,noexecstack,--gc-sections")
    # set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../assets/shark_inject/${CMAKE_ANDROID_ARCH_ABI}/)

    if (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=softfp -mfpu=vfpv3-d16")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=softfp -mfpu=vfpv3-d16")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--fix-cortex-a8")
        add_definitions(-DIOAPI_NO_64)
    elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
    elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpmath=sse -mstackrealign")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpmath=sse -mstackrealign")
        add_definitions(-DIOAPI_NO_64)
    endif()

endif()

add_definitions(
    -DFMT_HEADER_ONLY
    -DSPDLOG_FMT_EXTERNAL
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/
    ${CMAKE_CURRENT_SOURCE_DIR}/asio
    ${CMAKE_CURRENT_SOURCE_DIR}/fmt/include
    ${CMAKE_CURRENT_SOURCE_DIR}/nlohmann_json/include
    ${CMAKE_CURRENT_SOURCE_DIR}/spdlog/include
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib/contrib/minizip
)

set(DOBBY_GENERATE_SHARED OFF)
# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dobby)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/fmt)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/httplib)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/spdlog)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/nlohmann_json)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/zlib)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    # ${CMAKE_CURRENT_SOURCE_DIR}/dobby/include
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

# add_library(UnityCheat SHARED UnityCheat.cpp)
# target_link_libraries(UnityCheat dobby frida-gum utils_static)

add_library(UnityCheat SHARED UnityCheat2.cpp)
target_link_libraries(UnityCheat frida-gum utils_static)

add_executable(inject_service inject_service.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib/contrib/minizip/unzip.c
    ${CMAKE_CURRENT_SOURCE_DIR}/zlib/contrib/minizip/ioapi.c
    )
target_include_directories(inject_service PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/zlib)
add_dependencies(${PROJECT_NAME} zlibstatic)
target_link_libraries(inject_service zlibstatic frida-core)

if (CMAKE_BUILD_TYPE MATCHES "^Rel.*$")
set_target_properties(UnityCheat PROPERTIES LINK_FLAGS "-Wl,--gc-sections,-s,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/UnityCheat.version")
# set_target_properties(UnityCheat2 PROPERTIES LINK_FLAGS "-Wl,--gc-sections,-s,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/UnityCheat.version")
set_target_properties(inject_service PROPERTIES LINK_FLAGS "-Wl,--gc-sections,-s,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/inject_service.version")
endif()
