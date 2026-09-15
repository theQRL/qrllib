// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <xmss-alt/xmss_common.h>
#include <crypto/secure_memory.h>
#include "xmssBasic.h"
#include "xmss-alt/algsxmss.h"
#include <stdexcept>

XmssBasic::XmssBasic(const TSEED &seed,
                     unsigned char height,
                     eHashFunction hashFunction,
                     eAddrFormatType addrFormatType,
                     uint32_t wotsParamW)
        : XmssBase(seed, height, hashFunction, addrFormatType) {
//    PK format
//    32 root address
//    32 pub_seed
//
//    SK format
//    4  idx
//    32 sk_seed
//    32 sk_prf
//    32 pub_seed
//    32 root

    const uint32_t k = 2;
    const uint32_t w = wotsParamW;
    const uint32_t n = 32;

    XmssValidation::wots(w);
    TKEY replacement_sk(XmssValidation::SECRET_KEY_SIZE, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> replacement_sk_guard(replacement_sk);
    auto tmp = TKEY(64, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> tmp_guard(tmp);

    if (k >= height || (height - k) % 2) {
        throw std::invalid_argument("For BDS traversal, H - K must be even, with H > K >= 2!");
    }

    xmss_set_params(&params, n, height, w, k);
    if (!xmss_params_are_valid(&params)) {
        throw std::invalid_argument("Invalid XMSS parameters");
    }

    if (xmss_Genkeypair(_hashFunction,
                        &params,
                        tmp.data(),
                        replacement_sk.data(),
                        _seed.data()) != 0) {
        throw std::runtime_error("XMSS key generation failed");
    }
    qrllib::secure_memory::wipe_and_swap(_sk, replacement_sk);
}


TSIGNATURE XmssBasic::sign(const TMESSAGE &message) {
    validateBaseState();
    XmssValidation::wots(params.wots_par.w);
    if (!xmss_params_are_valid(&params) ||
        params.n != XmssValidation::N ||
        params.h != _height ||
        params.k != XmssValidation::BDS_K) {
        throw std::logic_error("Invalid XMSS parameter state");
    }
    if (getIndex() >= getNumberSignatures()) {
        throw std::invalid_argument("index too high");
    }

    auto signature = TSIGNATURE(getSignatureSize(params.wots_par.w), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> signature_guard(signature);

    if (xmss_Signmsg(_hashFunction,
                     &params,
                     _sk.data(),
                     signature.data(),
                     message.data(),
                     message.size()) != 0) {
        throw std::runtime_error("XMSS signing failed");
    }

    signature_guard.release();
    return signature;
}
