#!/bin/bash

INSTAL_DIR=$PWD/_install

aclocal -I m4
autoconf
autoheader
libtoolize --automake
automake --add-missing

if [ -e $INSTAL_DIR ]; then
	mkdir -p $INSTAL_DIR
fi

./configure --enable-debug --enable-verbose --prefix=$INSTAL_DIR 

make
make install
make dist

#compile samples.
cd ./samples
make clean
make
