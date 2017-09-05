#include <iostream>
#include "xmss.h"
#include "algsxmss.h"

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
    _seed = seed;

    xmss_Genkeypair(_pk.data(), _sk.data(), _seed.data(), height);
}

uint32_t Xmss::getSignatureSize()
{
    return static_cast<uint32_t>(4 + 32 + 67 * 32 + _height * 32);
}

uint32_t Xmss::getSecretKeySize()
{
    return 132;
}

TSIGNATURE Xmss::sign(const TMESSAGE &message)
{
    auto signature = TSIGNATURE(getSignatureSize(), 0);
    auto tmp = static_cast<TMESSAGE>(message);

    xmss_Signmsg(_sk.data(),
                 signature.data(),
                 tmp.data(),
                 _height);

    return signature;
}

bool Xmss::verify(const TMESSAGE &message,
                  TSIGNATURE &signature,
                  const TKEY &pk,
                  unsigned char height)
{
    return xmss_Verifysig(static_cast<TMESSAGE>(message).data(),
                          signature.data(),
                          _pk.data(),
                          height) == 0;
}
