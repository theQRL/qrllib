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

|           | Linux |     OSX<br>10.12     |  Windows<br>10 | Raspbian<br>? |
|-----------|:------------:|:-----------:|:--------:|:--------:|
|Python 3   | :white_check_mark: | :white_check_mark: |    :white_check_mark:     |     :white_check_mark:    |
|Webassembly (JS) |      :white_check_mark:       |     :white_check_mark:       |    :white_check_mark:     |     :white_check_mark:    |
|Golang     | :seedling: |     -       |    -     |     -    |
|Java       |      -       |     -       |    -     |     -    |

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
## Building from Source

#### Windows
For the purposes of these instructions Build Tools for Visual Studio 2017, CMake 3.10.2, Ninja 1.8.2, Python 3.6 and SWIG 3.0.12 were used, also ```c:\src``` was used for source files and ```c:\opt``` for other dependencies, adjust accordingly if choosing differently.

Note: You can use Microsoft MSBuild instead of Ninja Build by setting environment variable ```CMAKE_VS_GENERATOR=Visual Studio 15 2017 Win64```, however if you choose to install the pyqrllib package Python setuptools currently will not install it correctly.

Prerequisites:
- Install [Build Tools for Visual Studio](https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2017) selecting the *'Visual C++ build tools'* option, or install [Visual Studio Community Edition](https://www.visualstudio.com/vs/community/) selecting the *'Desktop Development for C++ workload'*.
- Install [Git for Windows](https://gitforwindows.org/) keeping the default option to use git from the command prompt.
- Install the latest stable [CMake x64 for Windows](https://cmake.org/download/), selecting to add CMake to system or user PATH.
- Install [Python 3 Windows x86-64](https://www.python.org/downloads/) selecting the option to '*Add Python 3.x to PATH*'. Optionally change the install location to ```c:\python37```, install the debugging symbols/binaries, and disable the path length limit.
- Download [SWIG](http://swig.org/) *(download swigwin)* and extract archive to ```c:\opt```
- Download [Ninja Build](https://github.com/ninja-build/ninja/releases) and extract ```ninja.exe``` to ```c:\opt\bin```

*Build Qrllib:*
```
git clone https://github.com/theQRL/qrllib.git c:\src\qrllib
cd \src\qrllib
set PATH=c:\opt\bin;c:\opt\swigwin-3.0.12;%PATH%
set CC=cl.exe
set CXX=cl.exe

python setup.py build
```

If the build succeeded you can perform further steps, issue the command ```python setup.py --help-commands``` to see other options, e.g.:
```
python setup.py test
python setup.py install
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
