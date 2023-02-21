
# include_directories(../frida/frida-android-${CMAKE_ANDROID_ARCH_ABI}/include)
# link_directories(../frida/frida-android-${CMAKE_ANDROID_ARCH_ABI}/lib)

set(CMAKE_C_FLAGS "-fdata-sections -ffunction-sections")
set(CMAKE_CXX_FLAGS "-fdata-sections -ffunction-sections")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs,ALL, -Wl,--gc-sections")

add_library(agent SHARED agent.c)
target_link_libraries(agent frida-core frida-gum log z)
set_target_properties(agent PROPERTIES LINK_FLAGS "-Wl,--gc-sections,-s,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/agent.version")

add_executable(inject inject.c)
target_link_libraries(inject frida-core frida-gum utils_static log z)

add_executable(victim victim.c)