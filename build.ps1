if (Test-Path $ENV:NDK) {
    $NDK = $ENV:NDK
}
else {
    $NDK = "$ENV:ANDROID_HOME\ndk\25.2.9519653"
}
# echo $NDK
function get_logic_core_count() {
    $cpu = get-wmiobject win32_processor
    # @($cpu).count CPU个数
    # $cpu.NumberOfLogicalProcessors 每个CPU的逻辑核心数
    return @($cpu).count * $cpu.NumberOfLogicalProcessors
}

$CPU_CORE_COUNT = $(get_logic_core_count)
$TOOLCHAIN_FILE = "${NDK}\build\cmake\android.toolchain.cmake"
$BUILD_TYPE = "Release"
$API_LEVEL = 24
$C = "$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
$CXX = "$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe"

if (Test-Path build_armeabi-v7a) { Remove-Item build_armeabi-v7a -Recurse }
cmake -S . -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DANDROID_PLATFORM="android-$API_LEVEL" -DANDROID_STL="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DANDROID_NDK="$NDK" -DCMAKE_C_COMPILER="$C" -DCMAKE_CXX_COMPILER="$CXX" -DANDROID_ABI=armeabi-v7a -B build_armeabi-v7a
cmake --build build_armeabi-v7a --parallel $CPU_CORE_COUNT
# cmake --install build_armeabi-v7

if (Test-Path build_arm64-v8a) { Remove-Item build_arm64-v8a -Recurse }
cmake -S . -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DANDROID_PLATFORM="android-$API_LEVEL" -DANDROID_STL="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DANDROID_NDK="$NDK" -DCMAKE_C_COMPILER="$C" -DCMAKE_CXX_COMPILER="$CXX" -DANDROID_ABI=arm64-v8a -B build_arm64-v8a
cmake --build build_arm64-v8a --parallel $CPU_CORE_COUNT
# cmake --install build_arm64-v8a

if (Test-Path build_x86) { Remove-Item build_x86 -Recurse }
cmake -S . -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DANDROID_PLATFORM="android-$API_LEVEL" -DANDROID_STL="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DANDROID_NDK="$NDK" -DCMAKE_C_COMPILER="$C" -DCMAKE_CXX_COMPILER="$CXX" -DANDROID_ABI=x86 -B build_x86
cmake --build build_x86 --parallel 4
# cmake --install build_x86

if (Test-Path build_x86_64) { Remove-Item build_x86_64 -Recurse }
cmake -S . -G "Ninja" -DCMAKE_SYSTEM_NAME=Android -DANDROID_PLATFORM="android-$API_LEVEL" -DANDROID_STL="c++_static" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" -DANDROID_NDK="$NDK" -DCMAKE_C_COMPILER="$C" -DCMAKE_CXX_COMPILER="$CXX" -DANDROID_ABI=x86_64 -B build_x86_64
cmake --build build_x86_64 --parallel 4
# cmake --install build_x86_64
