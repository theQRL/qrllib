#!/usr/bin/env bash
mkdir -p ./build
cd ./build
emconfigure cmake -DBUILD_WEBASSEMBLY=ON -DBUILD_PYTHON=OFF ..
emmake make
emcc --bind libjsqrl.so -O3 -o libjsqrl.js
cp ../src/tests_js/test.js .
node test.js
