$NDK = "$ENV:ANDROID_HOME\ndk\21.4.7075529"
$TOOLCHAIN_FILE = "$NDK\build\cmake\android.toolchain.cmake"
$BUILD_TYPE = "Release"
function remove_tempfile {
    if (Test-Path "CMakeFiles") {
        Remove-Item -Path CMakeFiles -Recurse
    }
    if (Test-Path ".ninja_log") {
        Remove-Item .ninja_log
    }
    if (Test-Path "cmake_install.cmake") {
        Remove-Item cmake_install.cmake
    }
    if (Test-Path "CMakeCache.txt") {
        Remove-Item CMakeCache.txt
    }
    if (Test-Path "build.ninja") {
        Remove-Item build.ninja
    }
    if (Test-Path ".ninja_deps") {
        Remove-Item .ninja_deps
    }
}

# echo $NDK
Remove-Item build_armeabi-v7a -Recurse
cmake -S . -B build_armeabi-v7a -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=21 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI=armeabi-v7a
cmake --build build_armeabi-v7a --parallel 4
# remove_tempfile

Remove-Item build_arm64-v8a -Recurse
cmake -S . -B build_arm64-v8a -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=21 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a
cmake --build build_arm64-v8a --parallel 4
# remove_tempfile

Remove-Item build_x86 -Recurse
cmake -S . -B build_x86 -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=21 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI=x86
cmake --build build_x86 --parallel 4
# remove_tempfile

Remove-Item build_x86_64 -Recurse
cmake -S . -B build_x86_64 -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=21 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI=x86_64
cmake --build build_x86_64 --parallel 4
# remove_tempfile
