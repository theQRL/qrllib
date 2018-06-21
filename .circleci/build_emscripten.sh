#!/usr/bin/env bash

emconfigure cmake -DBUILD_WEBASSEMBLY=ON -DCMAKE_BUILD_TYPE=Release
emmake make

# FIXME: Disable .mem for node.js until this gets fixed: https://github.com/kripken/emscripten/issues/2542
emcc --bind libjsqrl.so -s DISABLE_EXCEPTION_CATCHING=0 -O3 --memory-init-file 0  -o libjsqrl.js
emcc --bind libjsqrl.so -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -o web-libjsqrl.js
echo "QRLLIB=Module;" >> web-libjsqrl.js

# Fix paths of web-libjsqrl.wasm for web clients
sed -i 's/web-libjsqrl\.wasm/\/web-libjsqrl\.wasm/g' web-libjsqrl.js

# Copy to local dir in case it is run locally, the output is shared
if test -d /tmp/_circleci_local_build_repo; then cp *.js /tmp/_circleci_local_build_repo/tests/js/tmp/; fi
if test -d /tmp/_circleci_local_build_repo; then cp *.wasm /tmp/_circleci_local_build_repo/tests/js/tmp/; fi
if test -d /tmp/_circleci_local_build_repo; then chmod 777 /tmp/_circleci_local_build_repo/tests/js/tmp/*; fi

cp *.js tests/js/tmp/
cp *.wasm tests/js/tmp/

cp *.js build/
cp *.wasm build/
