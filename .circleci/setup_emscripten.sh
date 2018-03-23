#!/usr/bin/env bash
# This should be moved to the container

set -e
sudo mkhomedir_helper $(whoami)

cmake --version

# Get emscripten
cd ${HOME}
curl -O https://s3.amazonaws.com/mozilla-games/emscripten/releases/emsdk-portable.tar.gz
tar -xvzf emsdk-portable.tar.gz
cd emsdk-portable

./emsdk update
./emsdk install latest
./emsdk activate latest

source ./emsdk_env.sh
