// Appended to the emitted jsqrl bundles via --post-js (see
// .circleci/build_emscripten.sh).
//
// getRandomSeed(size = 48) returns a Uint8Vector of CSPRNG bytes suitable to
// pass directly to Xmss.fromParameters, so the secure path is the easy path
// for JS consumers. It is deliberately WebCrypto-only and fail-closed: if
// crypto.getRandomValues is unavailable it throws rather than degrading to a
// weaker source. There is intentionally no Math.random branch anywhere in
// this file — the shipped-bundle CI gate greps for exactly that.
Module['getRandomSeed'] = function (size) {
    if (size === undefined) {
        size = 48;
    }
    if (!(size > 0)) {
        throw new Error('getRandomSeed: size must be a positive integer');
    }

    var cryptoObj =
        (typeof globalThis !== 'undefined' && globalThis.crypto) ||
        (typeof self !== 'undefined' && self.crypto) ||
        (typeof window !== 'undefined' && window.crypto);

    if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
        throw new Error('Secure random number generation is not supported by this environment');
    }

    var bytes = new Uint8Array(size);
    cryptoObj.getRandomValues(bytes);

    // Tripwire against a dead platform RNG. Only meaningful for requests of
    // 16 bytes or more: shorter requests can legitimately be all zero.
    if (size >= 16) {
        var allZero = true;
        for (var i = 0; i < size; i++) {
            if (bytes[i] !== 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            throw new Error('Entropy source returned all zeroes');
        }
    }

    var vec = new Module.Uint8Vector();
    for (var j = 0; j < size; j++) {
        vec.push_back(bytes[j]);
    }
    return vec;
};
