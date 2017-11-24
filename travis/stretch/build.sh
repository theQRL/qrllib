#!/usr/bin/env bash
set -e
sudo mkhomedir_helper $(whoami)

BUILD_DIR="build"
cmake --version

cd /travis
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}
cmake -DCMAKE_C_COMPILER=gcc-${CC_VER} -DCMAKE_CXX_COMPILER=g++-${CC_VER} -DCMAKE_BUILD_TYPE=Release ${CMAKE_ARGS} /travis
make

if [ -n "${TEST:+1}" ]; then
  echo "Running Tests"
  if [[ ${CMAKE_ARGS} == *"BUILD_PYTHON=ON"* ]]; then
      cd /travis
      python3 setup.py test
  else
      export GTEST_COLOR=1
      ctest -VV
  fi
fi

if [ -n "${DEPLOY:+1}" ]; then
    cd /travis
    python3 setup.py sdist
fi

if [ -n "${BUILD_DIST:+1}" ]; then
    mkdir -p /travis/results # /travis is persistent

    cd /travis/travis
    tar xvf keys.tar
    gpg --import public.gpg || true
    gpg --import private.gpg || true

    # /build is inside the Docker container. we don't want to litter the host with persistent files. Especially useful if this is your dev machine
    # /build is already made by the Dockerfile, so let's prepare it for use by a normal user
    sudo chown -R $(id -u):$(id -g) /build
    cd /build
    pip3 download --no-deps pyqrllib
    export PYQRLLIB_TARBALL=$(find . -name "pyqrllib-*.tar.gz")
    py2dsc --with-python2=False --with-python3=True $PYQRLLIB_TARBALL
    cd deb_dist
    export PYQRLLIB_SLUG=$(find . -name "pyqrllib-*" -type d)
    cd $PYQRLLIB_SLUG
    dpkg-buildpackage -rfakeroot -k$GPGKEY
    # now that we're in /build/deb_dist/pyqrllib-0.2.9, we cd .. and copy
    cd /build/deb_dist
    find -maxdepth 1 -type f -exec cp {} /travis/results \;
fi
