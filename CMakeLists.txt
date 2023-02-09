cmake_minimum_required(VERSION 3.4.1)

project(shark_inject C CXX)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie")
# set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../assets/shark_inject/${CMAKE_ANDROID_ARCH_ABI}/)

add_executable(
        shark_inject
        shark_inject.cpp)

target_link_libraries(
        shark_inject)
