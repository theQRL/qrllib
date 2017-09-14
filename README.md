[![Build Status](https://travis-ci.org/jleni/qrllib.svg?branch=master)](https://travis-ci.org/jleni/qrllib)

# QRL Core Library

*WARNING: This is work in progress, changes might not be backward compatible.*

This library currently exposes the following functionality:  

- XMSS, XMSS_fast
- Shake128, Shake256, SHA2_256
- Hashchain seeds, etc.
- Helpers: seed generation, address generation, mnemonics

**Platform support**

|           | Ubuntu<br>16.04 |     OSX<br>10.12     |  Windows<br>10 | Raspbian<br>? | Chrome<br>(Webassembly) |
|-----------|:------------:|:-----------:|:--------:|:--------:|:-----------:|
|Python 2.7 | No           |     No      |    -     |     -    |     -       |
|Python 3.5 | pip package<br>missing  | pip package<br>missing |    -     |     -    |     -       |
|Golang     | wrapper<br>only |     -       |    -     |     -    |     -       |
|Java       |      -       |     -       |    -     |     -    |     -       |
|Javascript |      -       |     -       |    -     |     -    |     -       |

## Installing

We are currently working on pip wheels for the supported platforms. 

Installing this library in python should be as simple as:

```
pip install qrllib
```


## Build dependencies
*TODO: Update/complete this section*

Ubuntu:
```
pip install cmake
sudo apt install swig3.0 
sudo apt install openssl
sudo apt install python3.5-dev
````

OSX:
```
pip install cmake
brew install openssl
brew install swig
```

Windows:
```
TBD
```

Raspbian:

*Support will be provided in the near future*

```
TBD
```


**Some other dependencies:**

Golang and Java wrappers are currently experimental (By default they are disabled in cmake)

```
brew install go --cross-compile-common
```

## License

*This library is distributed under the MIT software license, see the accompanying file LICENSE or http://www.opensource.org/licenses/mit-license.php.*

Some of the code is based on the xmss-reference implementation that has been released in the public domain by their respective authors.

Most of third party code has been included as git submodules for future reference.
