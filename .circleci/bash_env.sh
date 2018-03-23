#!/usr/bin/env bash

bashrc_env_file="~/.bashrc"
emscripten_env_file="/root/emsdk-portable/emsdk_env.sh"

[ -f "${bashrc_env_file}" ] && source "${bashrc_env_file}"
[ -f "${emscripten_env_file}" ] && source "${emscripten_env_file}"
