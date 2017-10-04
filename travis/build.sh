#!/usr/bin/env bash

set -e

source ./travis/prepare.sh

case "${TRAVIS_OS_NAME}" in
    osx)
        echo "OSX BUILD"

        export BUILD_DIR=build
        mkdir -p ${BUILD_DIR}
        cd ${BUILD_DIR}
        cmake ${CMAKE_ARGS} ..
        make

        if [ -n "${TEST:+1}" ]; then
          echo "Running Tests"
          export GTEST_COLOR=1
          ctest -VV
        fi
        ;;

    linux)
        echo "LINUX BUILD " ${PLATFORM}

        USER_INFO="$( id -u ${USER} ):$( id -g ${USER} )"
        SHARE_USER_INFO="-v /etc/group:/etc/group:ro -v /etc/passwd:/etc/passwd:ro -u ${USER_INFO}"
        SHARE_SRC="-v $(pwd):/travis"

        docker stop $(docker ps -aq --filter name=builder) || true
        docker rm $(docker ps -aq --filter name=builder) || true
        docker build --file travis/Dockerfile.${PLATFORM} -t builder-${PLATFORM} .
        docker run -d --name builder ${SHARE_SRC} ${SHARE_USER_INFO} builder-${PLATFORM} tail -f /dev/null

        docker exec -t -e CC_VER=${CC_VER} -e CMAKE_ARGS=${CMAKE_ARGS} -e TEST=${TEST} -e DEPLOY=${DEPLOY} builder /build.sh
        ;;
    *)
        echo "UNSUPPORTED OS"
        exit 1
        ;;
esac
