#include "algsxmss.h"
#include "xmss.h"
#include <iostream>
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

TKEY XmssBase::getRoot()
{
    return TKEY(_pk.begin(), _pk.begin()+32);
}

TKEY XmssBase::getPKSeed()
{
    return TKEY(_pk.begin()+32, _pk.end());
}

uint32_t XmssBase::getIndex()
{
    // TODO: Check endianness issues
    // TODO: Review this according to IETF
    return _sk[0] << 24 + _sk[1] << 16 + _sk[2] << 8 + _sk[3];
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
}

TKEY XmssBase::getSKSeed()
{
    return TKEY(_sk.begin()+4, _sk.begin()+4+32);
}

TKEY XmssBase::getSKPRF()
{
    return TKEY(_sk.begin()+4+32, _sk.begin()+4+32+32);
}

std::string XmssBase::getAddress(const std::string &prefix)
{
    std::vector<unsigned char> key = getPK();
    return ::getAddress(prefix, key);
}