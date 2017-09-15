// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include "xmss.h"
#include "algsxmss.h"

Xmss::Xmss(const TSEED &seed, unsigned char height): XmssBase(seed, height)
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

    // FIXME: At the moment, the lib takes 48 bytes from the seed vector
    if (seed.size() != 48)
    {
        throw std::invalid_argument("Seed should be 48 bytes. Other values are not currently supported");
    }

    xmss_Genkeypair(_pk.data(), _sk.data(), _seed.data(), height);
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

bool Xmss::verify(const TMESSAGE &message,
            const TSIGNATURE &signature,
            const TKEY &pk,
            unsigned char height)
{
    // TODO: Fix constness in library
    auto tmp = static_cast<TSIGNATURE>(signature);
    return xmss_Verifysig(static_cast<TMESSAGE>(message).data(),
                          message.size(),
                          tmp.data(),
                          pk.data(),
                          height) == 0;
}

