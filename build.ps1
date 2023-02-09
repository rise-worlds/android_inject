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
mkdir build_armeabi-v7a
Set-Location build_armeabi-v7a
cmake -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=19 -DANDROID_PLATFORM=android-19 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DANDROID_ABI=armeabi-v7a -DCMAKE_ANDROID_ARCH_ABI=armeabi-v7a ..
ninja
# remove_tempfile
Set-Location ..

Remove-Item build_arm64-v8a -Recurse
mkdir build_arm64-v8a
Set-Location build_arm64-v8a
cmake -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=21 -DANDROID_PLATFORM=android-21 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DANDROID_ABI=arm64-v8a -DCMAKE_ANDROID_ARCH_ABI=arm64-v8a ..
ninja
# remove_tempfile
Set-Location ..

Remove-Item build_x86 -Recurse
mkdir build_x86
Set-Location build_x86
cmake -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=19 -DANDROID_PLATFORM=android-19 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DANDROID_ABI=x86 -DCMAKE_ANDROID_ARCH_ABI=x86 ..
ninja
# remove_tempfile
Set-Location ..

Remove-Item build_x86_64 -Recurse
mkdir build_x86_64
Set-Location build_x86_64
cmake -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=21 -DANDROID_PLATFORM=android-21 -DCMAKE_ANDROID_STL_TYPE=c++_static -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DANDROID_ABI=x86_64 -DCMAKE_ANDROID_ARCH_ABI=x86_64 ..
ninja
# remove_tempfile
Set-Location ..
