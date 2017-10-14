#include "algsxmss.h"
#include "xmss.h"
#include <iostream>
#include <xmss_common.h>
#include "xmssBase.h"
#include "misc.h"

XmssBase::XmssBase(const TSEED &seed, unsigned char height): _seed(seed), _height(height)
{
    if (seed.size() != 48)
    {
        throw std::invalid_argument("Seed should be 48 bytes. Other values are not currently supported");
    }
}

uint32_t XmssBase::getSignatureSize()
{
    // 4 + n + (len + h) * n)
    // FIXME: There could be consistency problems due to changes in N
    return static_cast<uint32_t>(4 + 32 + 67 * 32 + _height * 32);
}

uint32_t XmssBase::getPublicKeySize()
{
    return 64;
}

uint32_t XmssBase::getSecretKeySize()
{
    return 132;
}

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

constexpr size_t OFFSET_IDX = 0;
constexpr size_t OFFSET_SK_SEED = OFFSET_IDX + 4;
constexpr size_t OFFSET_SK_PRF = OFFSET_SK_SEED + 32;
constexpr size_t OFFSET_PUB_SEED = OFFSET_SK_PRF + 32;
constexpr size_t OFFSET_ROOT = OFFSET_PUB_SEED + 32;

uint32_t XmssBase::getIndex()
{
    // TODO: Check endianness issues
    // TODO: Review this according to IETF
    return  (_sk[0] << 24) +
            (_sk[1] << 16) +
            (_sk[2] << 8) +
            _sk[3];
}

TKEY XmssBase::getSKSeed()
{
    return TKEY(_sk.begin()+OFFSET_SK_SEED, _sk.begin()+OFFSET_SK_SEED+32);
}

TKEY XmssBase::getSKPRF()
{
    return TKEY(_sk.begin()+OFFSET_SK_PRF, _sk.begin()+OFFSET_SK_PRF+32);
}

TKEY XmssBase::getPKSeed()
{
    return TKEY(_sk.begin()+OFFSET_PUB_SEED, _sk.begin()+OFFSET_PUB_SEED+32);
}

TKEY XmssBase::getRoot()
{
    return TKEY(_sk.begin()+OFFSET_ROOT, _sk.begin()+OFFSET_ROOT+32);
}

uint32_t  XmssBase::setIndex(uint32_t new_index)
{
    // TODO: Check endianness issues
    _sk[3] = static_cast<unsigned char>(new_index & 0xFF);
    new_index >>= 8;
    _sk[2] = static_cast<unsigned char>(new_index & 0xFF);
    new_index >>= 8;
    _sk[1] = static_cast<unsigned char>(new_index & 0xFF);
    new_index >>= 8;
    _sk[0] = static_cast<unsigned char>(new_index & 0xFF);

    return getIndex();
}

TKEY XmssBase::getPK()
{
    // TODO: Improve and avoid copies / recalculation
    TKEY PK( getRoot() );
    auto pubseed = getPKSeed();

    PK.insert(PK.end(), pubseed.begin(), pubseed.end());

    return PK;
}

std::string XmssBase::getAddress(const std::string &prefix)
{
    std::vector<unsigned char> key = getPK();
    return ::getAddress(prefix, key);
}

bool XmssBase::verify(const TMESSAGE &message,
                      const TSIGNATURE &signature,
                      const TKEY &pk,
                      unsigned char height)
{
    xmss_params params;
    xmss_set_params(&params, 32, height, 16, 2 );

    // TODO: Fix constness in library
    auto tmp = static_cast<TSIGNATURE>(signature);
    return xmss_Verifysig(&params.wots_par,
                          static_cast<TMESSAGE>(message).data(),
                          message.size(),
                          tmp.data(),
                          pk.data(),
                          height) == 0;
}
