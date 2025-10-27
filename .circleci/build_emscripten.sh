#!/usr/bin/env bash

emcmake cmake -DBUILD_WEBASSEMBLY=ON -DCMAKE_BUILD_TYPE=Release
emmake make

# Build with modern emscripten (include wrapper object files)
emcc --bind CMakeFiles/jsqrl.dir/src/jswrapper/jsqrlwrapper.cpp.o libjsqrl.a libqrllib.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -o libjsqrl.js
emcc --bind CMakeFiles/jsqrl.dir/src/jswrapper/jsqrlwrapper.cpp.o libjsqrl.a libqrllib.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -o web-libjsqrl.js
emcc --bind CMakeFiles/jsqrl.dir/src/jswrapper/jsqrlwrapper.cpp.o libjsqrl.a libqrllib.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -s SINGLE_FILE=1 -o offline-libjsqrl.js
emcc --bind CMakeFiles/jsdilithium.dir/src/jswrapper/jsdilwrapper.cpp.o libjsdilithium.a libdilithium.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -s SINGLE_FILE=1 -o offline-libjsdilithium.js
emcc --bind CMakeFiles/jskyber.dir/src/jswrapper/jskybwrapper.cpp.o libjskyber.a libkyber.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -s SINGLE_FILE=1 -o offline-libjskyber.js
echo "QRLLIB=Module;" >> web-libjsqrl.js
echo "QRLLIB=Module;" >> offline-libjsqrl.js
echo "DILLIB=Module;" >> offline-libjsdilithium.js
echo "KYBLIB=Module;" >> offline-libjskyber.js

# Fix paths of web-libjsqrl.wasm for web clients (macOS compatible)
sed -i.bak 's/web-libjsqrl\.wasm/\/web-libjsqrl\.wasm/g' web-libjsqrl.js && rm -f web-libjsqrl.js.bak

# Copy to local dir in case it is run locally, the output is shared
if test -d /tmp/_circleci_local_build_repo; then cp *.js /tmp/_circleci_local_build_repo/tests/js/tmp/; fi
if test -d /tmp/_circleci_local_build_repo; then cp *.wasm /tmp/_circleci_local_build_repo/tests/js/tmp/; fi
if test -d /tmp/_circleci_local_build_repo; then chmod 777 /tmp/_circleci_local_build_repo/tests/js/tmp/*; fi

cp *.js tests/js/tmp/
cp *.wasm tests/js/tmp/

cp *.js build/
cp *.wasm build/
