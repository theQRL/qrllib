#!/usr/bin/env bash
mkdir -p ./build
cd ./build
echo "Running CMAKE..."
emconfigure cmake -DBUILD_WEBASSEMBLY=ON -DBUILD_PYTHON=OFF -DCMAKE_BUILD_TYPE=Release ..
echo "Building..."
emmake make
echo "Emscripten Binding/Optimizing..."
emcc --bind libjsqrl.so -O3 -o libjsqrl.js
emcc --bind libjsqrl.so -O3 -s WASM=1 -o web-libjsqrl.js
echo "Running test"
cp ../src/tests_js/test.js .
node test.js
