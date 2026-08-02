#!/usr/bin/env bash
set -e

# Pin the Emscripten toolchain. Which random-device shim the glue code carries
# is decided entirely by the Emscripten version, not by anything in this repo:
# older toolchains emitted a device with a silent Math.random fallback. An
# unnoticed toolchain downgrade would reintroduce it with no diff in any
# source file, so the version is asserted here and the emitted artifacts are
# checked below regardless. Bump EXPECTED_EMSCRIPTEN_VERSION deliberately,
# re-running the checks below, when upgrading the toolchain.
# Default matches the CI image (qrledger/qrl-docker-ci:noble). For local
# builds with a different toolchain, override deliberately, e.g.:
#   EXPECTED_EMSCRIPTEN_VERSION=4.0.22 ./.circleci/build_emscripten.sh
EXPECTED_EMSCRIPTEN_VERSION="${EXPECTED_EMSCRIPTEN_VERSION:-6.0.5}"
ACTUAL_EMSCRIPTEN_VERSION="$(emcc -dumpversion)"
case "$ACTUAL_EMSCRIPTEN_VERSION" in
  "$EXPECTED_EMSCRIPTEN_VERSION"*) ;;
  *)
    echo "FAIL: emcc version $ACTUAL_EMSCRIPTEN_VERSION does not match pinned $EXPECTED_EMSCRIPTEN_VERSION"
    echo "      (set EXPECTED_EMSCRIPTEN_VERSION to override deliberately)"
    exit 1
    ;;
esac

emcmake cmake -DBUILD_WEBASSEMBLY=ON -DCMAKE_BUILD_TYPE=Release
emmake make

# Build with modern emscripten (include wrapper object files)
# libjsqrl.js must be self-contained: package.json only publishes the .js, and
# modern emscripten defaults to WASM=1 with an external .wasm sidecar. SINGLE_FILE
# embeds the wasm so the published module loads standalone (as the old asm.js
# default output did) under node, browsers and bundlers alike.
# getRandomSeed.js appends a fail-closed WebCrypto seed helper to the qrl
# bundles so consumers have a correct entropy call to reach for.
POST_JS="--post-js src/jswrapper/getRandomSeed.js"
emcc --bind CMakeFiles/jsqrl.dir/src/jswrapper/jsqrlwrapper.cpp.o libjsqrl.a libqrllib.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -s SINGLE_FILE=1 $POST_JS -o libjsqrl.js
emcc --bind CMakeFiles/jsqrl.dir/src/jswrapper/jsqrlwrapper.cpp.o libjsqrl.a libqrllib.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 $POST_JS -o web-libjsqrl.js
emcc --bind CMakeFiles/jsqrl.dir/src/jswrapper/jsqrlwrapper.cpp.o libjsqrl.a libqrllib.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -s SINGLE_FILE=1 $POST_JS -o offline-libjsqrl.js
emcc --bind CMakeFiles/jsdilithium.dir/src/jswrapper/jsdilwrapper.cpp.o libjsdilithium.a libdilithium.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -s SINGLE_FILE=1 -o offline-libjsdilithium.js
emcc --bind CMakeFiles/jskyber.dir/src/jswrapper/jskybwrapper.cpp.o libjskyber.a libkyber.a libshasha.a -s DISABLE_EXCEPTION_CATCHING=0 -O3 -s WASM=1 -s SINGLE_FILE=1 -o offline-libjskyber.js
echo "QRLLIB=Module;" >> web-libjsqrl.js
echo "QRLLIB=Module;" >> offline-libjsqrl.js
echo "DILLIB=Module;" >> offline-libjsdilithium.js
echo "KYBLIB=Module;" >> offline-libjskyber.js

# Fix paths of web-libjsqrl.wasm for web clients (macOS compatible)
sed -i.bak 's/web-libjsqrl\.wasm/\/web-libjsqrl\.wasm/g' web-libjsqrl.js && rm -f web-libjsqrl.js.bak

# --- RNG shim regression gate --------------------------------------------------
# The security property of every shipped bundle is decided at build time by
# the toolchain, not by source in this repo. Assert it on the artifacts:
#   1. every bundle has a WebCrypto path (getRandomSeed helper or the modern
#      fail-closed emscripten shim), and
#   2. no bundle carries any Math.random branch that a missing WebCrypto
#      could silently fall back to.
for f in libjsqrl.js web-libjsqrl.js offline-libjsqrl.js offline-libjsdilithium.js offline-libjskyber.js; do
  if ! grep -q 'getRandomValues' "$f"; then
    echo "FAIL: $f contains no getRandomValues"
    exit 1
  fi
  if grep -q 'Math\.random' "$f"; then
    echo "FAIL: $f contains a Math.random RNG device"
    exit 1
  fi
done

# The XMSS wasm must remain a pure deterministic sink: it receives its seed
# from the caller and must not be able to open an entropy device internally.
# (The kyber/dilithium wasm legitimately reads /dev/urandom and is excluded.)
if LC_ALL=C grep -q 'urandom\|random_device\|getentropy' web-libjsqrl.wasm; then
  echo "FAIL: web-libjsqrl.wasm contains entropy-source markers (urandom/random_device/getentropy)"
  exit 1
fi
echo "RNG shim assertions passed"
# ------------------------------------------------------------------------------

# Copy to local dir in case it is run locally, the output is shared
if test -d /tmp/_circleci_local_build_repo; then cp *.js /tmp/_circleci_local_build_repo/tests/js/tmp/; fi
if test -d /tmp/_circleci_local_build_repo; then cp *.wasm /tmp/_circleci_local_build_repo/tests/js/tmp/; fi
if test -d /tmp/_circleci_local_build_repo; then chmod 777 /tmp/_circleci_local_build_repo/tests/js/tmp/*; fi

cp *.js tests/js/tmp/
cp *.wasm tests/js/tmp/

cp *.js build/
cp *.wasm build/
