#!/bin/sh
cd /travis
mkdir build
cd build
cmake -DCMAKE_C_COMPILER=gcc-$CC_VER -DCMAKE_CXX_COMPILER=g++-$CC_VER ../
make
