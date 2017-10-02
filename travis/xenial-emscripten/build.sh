#!/usr/bin/env bash

BUILD_DIR="build"

set -e

cd /travis
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

source ./root/emsdk-portable/emsdk_env.sh

emconfigure cmake -DBUILD_WEBASSEMBLY=ON ${CMAKE_ARGS} -DCMAKE_BUILD_TYPE=Release /travis

echo "Building..."
emmake make

echo "Emscripten Binding/Optimizing..."
emcc --bind libjsqrl.so -O3 -o libjsqrl.js
emcc --bind libjsqrl.so -O3 -s WASM=1 -o web-libjsqrl.js


if [ -n "${TEST:+1}" ]; then
  echo "Running Tests"
  cp ./travis/src/tests_js/test.js .
  node test.js
fi

if [ -n "${DEPLOY:+1}" ]; then
    cd /travis
    python3 setup.py sdist
fi
