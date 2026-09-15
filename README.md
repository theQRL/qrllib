[![PyPI version](https://img.shields.io/badge/PyPI-1.3.0-blue.svg)](https://pypi.org/project/pyqrllib/1.3.0/)
[![npm version](https://img.shields.io/badge/npm-1.3.0-red.svg)](https://www.npmjs.com/package/qrllib/v/1.3.0)
[![CircleCI](https://circleci.com/gh/theQRL/qrllib.svg?style=svg)](https://circleci.com/gh/theQRL/qrllib)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/23da5bbcb4fc4b6ba0c118f181aba24e)](https://www.codacy.com/gh/theQRL/qrllib/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=theQRL/qrllib&amp;utm_campaign=Badge_Grade)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/theQRL/qrllib/master/LICENSE)

# QRL core library

> [!NOTE]
> This code relates to version 1.x of QRL, the world's first open-source PQ
> blockchain, which has been securing digital assets since December 2016.
> The next generation of QRL, version 2.0, is in development and has its own
> repositories. See [this discussion page](https://github.com/orgs/theQRL/discussions/2).

> This project is under active development. Interfaces and serialized formats
> may change without backward compatibility.

qrllib contains the cryptographic code used by QRL and interfaces for C++,
Python, Rust, Go, and JavaScript/WebAssembly. It includes:

- QRL's stateful XMSS and `XmssFast` implementations using WOTS+;
- SHA2-256, SHAKE128, and SHAKE256 hashing;
- seed, address, mnemonic, and hash-chain helpers;
- historical Dilithium and Kyber implementations retained for QRL
  compatibility.

## Cryptographic standards status

The XMSS parameters selected for QRL predate NIST's standardization in
[SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final). The formats and
parameter choices implemented here are QRL-specific.

The Kyber and Dilithium APIs use pre-standard candidate-era implementations
retained for QRL v1 compatibility. They do not implement ML-KEM (FIPS 203) or
ML-DSA (FIPS 204).

The XMSS references below explain state-management risks. Citing them does not
imply standards compliance.

## XMSS signing state

An XMSS OTS index must never be reused with the same private key. Reusing a
private-key state removes the scheme's security guarantee and
can make signature forgery possible. See
[RFC 8391 section 1.1](https://www.rfc-editor.org/rfc/rfc8391.html#section-1.1).

Best practice for qrllib is to keep signing under application and user control,
backed by an independent, durable ledger of every OTS index reserved or
consumed by a signing attempt. When a signature is returned, associate the
signature or its stable identifier with that index in the ledger. The calling
application must coordinate the ledger across processes, signer objects,
backups, and restored seeds. This enforces the application-level single-use
requirement in
[RFC 8391 section 4.1.12](https://www.rfc-editor.org/rfc/rfc8391.html#section-4.1.12).
Do not rely only on a signer object's in-memory index.

Reserve and persist an index before asking qrllib to sign. Treat the index as
consumed even if signing fails or the process stops before returning a
signature. This ordering is consistent with
[RFC 8391 section 4.1.9](https://www.rfc-editor.org/rfc/rfc8391.html#section-4.1.9),
which updates the private-key state before releasing a signature. A durable
high-water mark is sufficient only if every lower reserved or skipped index is
permanently burned.

Copying an `XmssFast` object duplicates its private key and current index. Each
copy then advances independently. Moving a C++ object is the safer way to
transfer signing ownership. Reconstructing a signer from the same seed also
reconstructs the same key, so it must use the same external OTS record.

Methods such as `getSK`, `getSeed`, `getHexSeed`, and `getMnemonic` explicitly
export private key material. The returned vector or string belongs to the
caller and may be copied again by the language runtime. qrllib explicitly
erases selected secret-bearing storage that it owns, but this is defense in
depth rather than a guarantee that no compiler, runtime, allocator, operating
system, or third-party copy remains. It cannot erase an exported value after
return. Export secrets only when needed, keep them out of logs, and overwrite
mutable caller-owned buffers before releasing them.

The Go bindings do not attach finalizers to SWIG vector proxies. After copying
a top-level returned `UcharVector` into Go-owned memory, call the matching
module's `DeleteUcharVector` function; use
`goqrllib.DeleteX_string_list_list` for the nested result from
`GetHashChainSeed`. Element vectors obtained through that nested proxy's `Get`
method borrow the outer object and must not be deleted separately. These
deletion functions wipe the C++ vector storage before freeing it. Go-owned byte
slices and strings remain under the caller's control and must be overwritten
separately when appropriate.

Coverage differs by backend. The native historical Dilithium and Kyber
compatibility path erases wrapper state and its directly owned sensitive work
buffers. The pinned `pqcrypto` dependencies used by the Rust wrappers do not
erase every internal stack and Keccak workspace, so their coverage remains
partial.

## Tested platforms

CircleCI tests core C++ on Linux x64, macOS arm64, and Windows x64; historical
Dilithium and Kyber on Linux x64 and macOS arm64; and Python, Rust, Go, and
JavaScript/WebAssembly on Linux x64. GitHub Actions builds releases.

## Install the Python package

The Python package is published as `pyqrllib`:

```bash
python3 -m pip install pyqrllib
```

The Python package is tested on Linux x64.

## Build from source

Clone the submodules and install CMake 3.20 or later plus a C++17 compiler for
the commands below. Python and Go bindings also require SWIG. The JavaScript
build requires the Emscripten version checked by
`.circleci/build_emscripten.sh`.

```bash
git clone --recurse-submodules https://github.com/theQRL/qrllib.git
cd qrllib
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The Rust implementation requires Rust 1.78 or later. Run its tests with:

```bash
cargo test
```

For the Python extension and tests:

```bash
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -e '.[testing]'
python3 -m pytest tests/python
```

## JavaScript/WebAssembly development

With the pinned Emscripten toolchain active:

```bash
./.circleci/build_emscripten.sh
cd tests/js
npm ci
npm test
npm run test:browser
```

The generated files are copied to `tests/js/tmp` and `build`. The npm package
publishes the declared bundles from `build`; it does not currently define a
root `main` or `exports` entry point.

## License

qrllib is distributed under the [MIT license](LICENSE). Parts of the XMSS code
derive from the public-domain reference implementation by Andreas Huelsing and
Joost Rijneveld. Several third-party components are included as Git submodules.
