// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <stdexcept>
#include <xmss_common.h>
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

    _sk = TKEY(132, 0);
    auto tmp = TKEY(64, 0);

    // FIXME: At the moment, the lib takes 48 bytes from the seed vector
    if (seed.size() != 48)
    {
        throw std::invalid_argument("Seed should be 48 bytes. Other values are not currently supported");
    }

    xmss_Genkeypair(tmp.data(), _sk.data(), _seed.data(), height);
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


