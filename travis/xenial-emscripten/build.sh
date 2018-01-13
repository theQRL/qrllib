#!/usr/bin/env bash
set -e
sudo mkhomedir_helper $(whoami)

BUILD_DIR="build"
cmake --version

# Get emscripten
cd ${HOME}
curl -O https://s3.amazonaws.com/mozilla-games/emscripten/releases/emsdk-portable.tar.gz
tar -xvzf emsdk-portable.tar.gz
cd emsdk-portable

./emsdk update &> /dev/null
./emsdk install latest &> /dev/null
./emsdk activate latest &> /dev/null

source ./emsdk_env.sh

cd /travis
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

emconfigure cmake -DBUILD_WEBASSEMBLY=ON ${CMAKE_ARGS} -DCMAKE_BUILD_TYPE=Release /travis

echo "Building..."
emmake make

echo "Emscripten Binding/Optimizing..."
#FIXME: Disable .mem for node.js until this gets fixed: https://github.com/kripken/emscripten/issues/2542
emcc --bind libjsqrl.so -O3 --memory-init-file 0  -o libjsqrl.js
emcc --bind libjsqrl.so -O3 -s WASM=1 -o web-libjsqrl.js
echo "QRLLIB=Module;" >> web-libjsqrl.js

# Fix pathing of web-libjsqrl.wasm for web clients
sed -i 's/web-libjsqrl\.wasm/\/web-libjsqrl\.wasm/g' web-libjsqrl.js

if [ -n "${TEST:+1}" ]; then
  echo "Running Tests"
  cp ./travis/tests_js/test.js .
  node test.js
fi

if [ -n "${DEPLOY:+1}" ]; then
    echo "******** Prepare deployment package HERE ********"
fi
