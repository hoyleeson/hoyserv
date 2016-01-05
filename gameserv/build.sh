#!/bin/bash

INSTAL_DIR=$PWD/_install

aclocal
autoconf
autoheader
libtoolize --automake
automake --add-missing

if [ -e $INSTAL_DIR ]; then
	mkdir -p $INSTAL_DIR
fi

./configure --enable-debug --prefix=$INSTAL_DIR 

make
make install

#compile samples.
cd ./samples
make clean
make
