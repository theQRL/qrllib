#!/bin/sh

BUILD_DIR="cmake-build-${PLATFORM}"

cd /travis
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}
cmake -DCMAKE_C_COMPILER=gcc-${CC_VER} -DCMAKE_CXX_COMPILER=g++-${CC_VER} /travis
make
