if (Test-Path $ENV:NDK) {
    $NDK = $ENV:NDK
} else {
    $NDK = "$ENV:ANDROID_HOME\ndk\25.2.9519653"
}
# echo $NDK

$TOOLCHAIN_FILE = "$NDK\build\cmake\android.toolchain.cmake"
$BUILD_TYPE = "Release"
$API_LEVEL = 24

if (Test-Path build_armeabi-v7a) { Remove-Item build_armeabi-v7a -Recurse }
cmake -S . -B build_armeabi-v7a -G "Ninja" -DCMAKE_SYSTEM_NAME=Android --toolchain "$TOOLCHAIN_FILE" -DCMAKE_SYSTEM_VERSION="$API_LEVEL" -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" -DCMAKE_ANDROID_STL_TYPE="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI="armeabi-v7a"
cmake --build build_armeabi-v7a --parallel 4
# cmake --install build_armeabi-v7

if (Test-Path build_arm64-v8a) { Remove-Item build_arm64-v8a -Recurse }
cmake -S . -B build_arm64-v8a -G "Ninja" -DCMAKE_SYSTEM_NAME=Android --toolchain "$TOOLCHAIN_FILE" -DCMAKE_SYSTEM_VERSION="$API_LEVEL" -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" -DCMAKE_ANDROID_STL_TYPE="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI="arm64-v8a"
cmake --build build_arm64-v8a --parallel 4
# cmake --install build_arm64-v8a

if (Test-Path build_x86) { Remove-Item build_x86 -Recurse }
cmake -S . -B build_x86 -G "Ninja" -DCMAKE_SYSTEM_NAME=Android --toolchain "$TOOLCHAIN_FILE" -DCMAKE_SYSTEM_VERSION="$API_LEVEL" -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" -DCMAKE_ANDROID_STL_TYPE="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI="x86"
cmake --build build_x86 --parallel 4
# cmake --install build_x86

if (Test-Path build_x86_64) { Remove-Item build_x86_64 -Recurse }
cmake -S . -B build_x86_64 -G "Ninja" -DCMAKE_SYSTEM_NAME=Android --toolchain "$TOOLCHAIN_FILE" -DCMAKE_SYSTEM_VERSION="$API_LEVEL" -DANDROID_NATIVE_API_LEVEL="$API_LEVEL" -DCMAKE_ANDROID_STL_TYPE="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DCMAKE_ANDROID_NDK="$NDK" -DCMAKE_ANDROID_ARCH_ABI="x86_64"
cmake --build build_x86_64 --parallel 4
# cmake --install build_x86_64
