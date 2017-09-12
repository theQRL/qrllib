// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include "xmss.h"
#include "algsxmss.h"
#include "misc.h"

Xmss::Xmss(const TSEED &seed, unsigned char height): _height(height)
{
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
// TODO: Use a union? to operated on partial fields

    _sk = TKEY(132, 0);
    _pk = TKEY(64, 0);

    // FIXME: At the moment, the lib takes 32 bytes from the seed vector
    _seed = seed;

    xmss_Genkeypair(_pk.data(), _sk.data(), _seed.data(), height);
}

uint32_t Xmss::getSignatureSize()
{
    return static_cast<uint32_t>(4 + 32 + 67 * 32 + _height * 32);
}

uint32_t Xmss::getPublicKeySize()
{
    return 64;
}

uint32_t Xmss::getSecretKeySize()
{
    return 132;
}

TKEY Xmss::getRoot()
{
    return TKEY(_pk.begin(), _pk.begin()+32);
}

TKEY Xmss::getPKSeed()
{
    return TKEY(_pk.begin()+32, _pk.end());
}

uint32_t Xmss::getIndex()
{
    // TODO: Review this according to IETF
    return _sk[0] << 24 + _sk[1] << 16 + _sk[2] << 8 + _sk[0];
}

TKEY Xmss::getSKSeed()
{
    return TKEY(_sk.begin()+4, _sk.begin()+4+32);
}

TKEY Xmss::getSKPRF()
{
    return TKEY(_sk.begin()+4+32, _sk.begin()+4+32+32);
}

TSIGNATURE Xmss::sign(const TMESSAGE &message)
{
    // TODO: Fix constness in library
    auto signature = TSIGNATURE(getSignatureSize(), 0);

    xmss_Signmsg(_sk.data(),
                 signature.data(),
                 static_cast<TMESSAGE>(message).data(),
                 message.size(),
                 _height);

    return signature;
}

bool verify(const TMESSAGE &message,
            const TSIGNATURE &signature,
            const TKEY &pk,
            int height)
{
    // TODO: Fix constness in library
    auto tmp = static_cast<TSIGNATURE>(signature);
    return xmss_Verifysig(static_cast<TMESSAGE>(message).data(),
                          message.size(),
                          tmp.data(),
                          pk.data(),
                          height) == 0;
}

