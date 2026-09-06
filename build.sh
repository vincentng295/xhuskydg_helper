#!/usr/bin/env bash

set -euo pipefail

build_mode="${1:-release}"

cd "$(dirname "$0")"

ANDROID_NDK_HOME=./android-ndk-r23b
export PATH=${PATH}:${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin

rm -rf out
mkdir -p out/build

( cat << EOF
arm64-v8a aarch64-linux-android31-clang++
armeabi-v7a armv7a-linux-androideabi31-clang++
x86 i686-linux-android31-clang++
x86_64 x86_64-linux-android31-clang++
EOF
) | while read line; do
    ARCH="$(echo $line | awk '{ print $1 }')"
    CXX="$(echo $line | awk '{ print $2 }')"
    if [ ! -z "$ARCH" ]; then
        mkdir "out/build/${ARCH}"
        ${CXX} \
    native/jni/main.cpp \
    native/jni/openxtun.cpp \
    native/jni/dnsjson.cpp \
    -static \
    -std=c++17 \
    -o "out/build/${ARCH}/xhuskydg_helper"
    fi
done

zip -r9 out/xhuskydg_helper-release.zip out/build