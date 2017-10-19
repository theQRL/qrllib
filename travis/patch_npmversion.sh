#!/usr/bin/env bash
pushd . > /dev/null
cd $( dirname "${BASH_SOURCE[0]}" )
cd ..

set -e
QRLLIB_VERSION=$(git describe --tags)

sed -i 's|__QRLLIB_VERSION__|'${QRLLIB_VERSION}'|g' package.json

popd > /dev/null
