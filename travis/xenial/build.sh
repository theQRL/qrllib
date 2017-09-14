#!/bin/sh
cd /travis;
cmake -DCMAKE_C_COMPILER=gcc-$CC_VER -DCMAKE_CXX_COMPILER=g++-$CC_VER . &&
make &&
chmod +x travis &&
./travis
