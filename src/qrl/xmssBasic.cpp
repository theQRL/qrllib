// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <xmss-alt/xmss_common.h>
#include "xmssBasic.h"
#include "xmss-alt/algsxmss.h"
#include <stdexcept>

XmssBasic::XmssBasic(const TSEED &seed,
                     unsigned char height,
                     eHashFunction hashFunction,
                     eAddrFormatType addrFormatType)
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

    _sk = TKEY(132, 0);
    auto tmp = TKEY(64, 0);

    // FIXME: At the moment, the lib takes 48 bytes from the seed vector
    if (seed.size() != 48) {
        throw std::invalid_argument("Seed should be 48 bytes. Other values are not currently supported");
    }

    const uint32_t k = 2;
    const uint32_t w = 16;
    const uint32_t n = 32;

    if (k >= height || (height - k) % 2) {
        throw std::invalid_argument("For BDS traversal, H - K must be even, with H > K >= 2!");
    }

    xmss_set_params(&params, n, height, w, k);

    xmss_Genkeypair(_hashFunction,
                    &params,
                    tmp.data(),
                    _sk.data(),
                    _seed.data());
}


TSIGNATURE XmssBasic::sign(const TMESSAGE &message) {
    auto signature = TSIGNATURE(getSignatureSize(), 0);

    xmss_Signmsg(_hashFunction,
                 &params,
                 _sk.data(),
                 signature.data(),
                 static_cast<TMESSAGE>(message).data(),
                 message.size());

    return signature;
}


