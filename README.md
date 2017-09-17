[![PyPI version](https://badge.fury.io/py/pyqrllib.svg)](https://badge.fury.io/py/pyqrllib)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4b34f51616d94362b3447bb2f4df765a)](https://www.codacy.com/app/jleni/qrllib_QRL?utm_source=github.com&utm_medium=referral&utm_content=theQRL/qrllib&utm_campaign=badger)
[![Build Status](https://travis-ci.org/theQRL/qrllib.svg?branch=master)](https://travis-ci.org/theQRL/qrllib)
[![Build Status-Windows](https://ci.appveyor.com/api/projects/status/j2koo6iexyji0vfj/branch/master?svg=true)](https://ci.appveyor.com/project/jleni/qrllib-mgkan/branch/master)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/theQRL/qrllib/master/LICENSE)

# QRL Core Library

*WARNING: This is work in progress, changes might not be backward compatible.*

This library currently exposes the following functionality:  

- XMSS, XMSS_fast
- Shake128, Shake256, SHA2_256
- Hashchain seeds, etc.
- Helpers: seed generation, address generation, mnemonics

**Platform support**

|           | Linux |     OSX<br>10.12     |  Windows<br>10 | Raspbian<br>? | Chrome<br>(Webassembly) |
|-----------|:------------:|:-----------:|:--------:|:--------:|:-----------:|
|Python 2   | :x:           |    :x:      |    -     |     -    |     -       |
|Python 3   | :white_check_mark: | :white_check_mark: |    :seedling:     |     :question:    |     :question:       |
|Golang     | wrapper<br>generation only |     -       |    -     |     -    |     -       |
|Java       |      -       |     -       |    -     |     -    |     -       |
|Javascript |      -       |     -       |    -     |     -    |     -       |

## Installing

*TODO: Work in progress.*

#### Ubuntu
```
sudo apt -y install swig3.0 python3.5-dev
pip3 install pyqrllib
````

#### OSX

If you dont have brew yet, you should:
```bash
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

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

*Experimental. Feedback is welcomed*

```
sudo apt -y install swig3.0 python3.5-dev
pip3 install pyqrllib
```

#### Miscellaneous

Golang and Java wrappers are currently experimental (By default they are disabled in cmake)

```
brew install go --cross-compile-common
```

## License

*This library is distributed under the MIT software license, see the accompanying file LICENSE or http://www.opensource.org/licenses/mit-license.php.*

Some of the code is based on the xmss-reference implementation that has been released in the public domain by their respective authors.

Most of third party code has been included as git submodules for future reference.
