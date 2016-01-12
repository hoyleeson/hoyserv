#!/bin/bash

NDK_DIR=/home/lixinhai/develop_tools/android_ndk/android-ndk-r10e
SYSROOT=$NDK_DIR/platforms/android-21/arch-arm/
TOOLCHAIN=$NDK_DIR/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64

export CC="$TOOLCHAIN/bin/arm-linux-androideabi-gcc --sysroot=$SYSROOT"

INSTAL_DIR=$PWD/_android_install

if [ -e $INSTAL_DIR ]; then
	mkdir -p $INSTAL_DIR
fi

./configure  --enable-verbose --prefix=$INSTAL_DIR --host=arm-linux-androideabi

make
make install

