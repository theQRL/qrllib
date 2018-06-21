[![PyPI version](https://badge.fury.io/py/pyqrllib.svg)](https://badge.fury.io/py/pyqrllib)
[![npm version](https://badge.fury.io/js/qrllib.svg)](https://badge.fury.io/js/qrllib)
[![Build Status](https://travis-ci.org/theQRL/qrllib.svg?branch=master)](https://travis-ci.org/theQRL/qrllib)
[![CircleCI](https://circleci.com/gh/theQRL/qrllib.svg?style=svg)](https://circleci.com/gh/theQRL/qrllib)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4b34f51616d94362b3447bb2f4df765a)](https://www.codacy.com/app/jleni/qrllib_QRL?utm_source=github.com&utm_medium=referral&utm_content=theQRL/qrllib&utm_campaign=badger)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/theQRL/qrllib/master/LICENSE)

# QRL Core Library

*WARNING: This is work in progress, changes might not be backward compatible.*

This library currently exposes the following functionality:  

- XMSS, XMSS_fast
- Shake128, Shake256, SHA2_256
- Hashchain seeds, etc.
- Helpers: seed generation, address generation, mnemonics

**Platform support**

|           | Linux |     OSX<br>10.12     |  Windows<br>10 |
|-----------|:------------:|:-----------:|:--------:|
|Python 3   | :white_check_mark: | :white_check_mark: |    :seedling:     |
|Webassembly (JS) |      :white_check_mark:       |     :white_check_mark:       |    :white_check_mark:     |
|Golang     | :seedling: |     -       |    -     |
|Java       |      -       |     -       |    -     |

## Installing

#### Ubuntu
```
sudo apt -y install swig3.0 python3-dev build-essential cmake ninja-build pkg-config
pip3 install pyqrllib
````

#### OSX

If you dont have brew yet, we think you should :) Install brew following the instructions here: [https://brew.sh/](https://brew.sh/)

Now install some dependencies

```bash
brew install cmake python3 swig
pip3 install pyqrllib
```

#### Windows
```
TBD
```

#### Raspbian

```
sudo apt -y install swig3.0 python3-dev build-essential cmake ninja-build
sudo pip3 install -U setuptools
sudo pip3 install -U pyqrllib
```

#### Miscellaneous

Golang and Java wrappers are currently experimental (By default they are disabled in cmake)

```
brew install go --cross-compile-common
```

## Development

#### Emscripten

In order to compile the webassembly and run node.js tests you first need to install CircleCI CLI:

https://circleci.com/docs/2.0/local-cli/#installing-the-circleci-local-cli-on-macos-and-linux-distros

Then run the following command

```
circleci build --job build_emscripten
```

This will compile and test the webassembly. Output files will be copied over to `tests/js/tmp`

You can then run node.js locally using npm.

## License

*This library is distributed under the MIT software license, see the accompanying file LICENSE or http://www.opensource.org/licenses/mit-license.php.*

Some of the code is based on the xmss-reference implementation that has been released in the public domain by their respective authors.

Most of third party code has been included as git submodules for future reference.
