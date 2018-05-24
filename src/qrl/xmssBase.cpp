#include "xmss-alt/algsxmss.h"
#include "xmssBasic.h"
#include <iostream>
#include <PicoSHA2/picosha2.h>
#include "qrlHelper.h"

XmssBase::XmssBase(const TSEED& seed,
        uint8_t height,
        eHashFunction hashFunction,
        eAddrFormatType addrFormatType)
        :_seed(seed),
         _height(height),
         _hashFunction(hashFunction),
         _addrFormatType(addrFormatType)
{
    if (seed.size()!=48) {
        throw std::invalid_argument("Seed should be 48 bytes. Other values are not currently supported");
    }
}

XmssBase::XmssBase(const TSEED& extended_seed)
{
    if (extended_seed.size()!=51) {
        throw std::invalid_argument("Extended seed should be 51 bytes. Other values are not currently supported");
    }

    auto desc = QRLDescriptor::fromExtendedSeed(extended_seed);

    _seed = std::vector<uint8_t>(
            extended_seed.cbegin()+QRLDescriptor::getSize(),
            extended_seed.cend());

    _height = desc.getHeight();
    _hashFunction = desc.getHashFunction();
    _addrFormatType = desc.getAddrFormatType();
}

uint32_t XmssBase::getSignatureSize()
{
    // 4 + n + (len + h) * n)
    return static_cast<uint32_t>(4+32+67*32+_height*32);
}

uint8_t XmssBase::getHeightFromSigSize(size_t sigSize)
{
    const uint32_t min_size = 4+32+67*32;    // FIXME: Move these values to constants
    if (sigSize < min_size)
    {
        throw std::invalid_argument("Invalid signature size");
    }

    if ((sigSize-4)%32!=0) {
        throw std::invalid_argument("Invalid signature size");
    }

    auto height = (sigSize - min_size)/32;

    return static_cast<uint8_t>(height);
}

uint32_t XmssBase::getPublicKeySize()
{
    return QRLDescriptor::getSize()+64;
}

uint32_t XmssBase::getSecretKeySize()
{
    return 132;
}

//    PK format
//     2 QRL_DESCRIPTOR
//    32 root address
//    32 pub_seed
//
//    SK format
//    4  idx
//    32 sk_seed
//    32 sk_prf
//    32 pub_seed
//    32 root

// FIXME: Use a union for this
constexpr size_t OFFSET_IDX = 0;

constexpr size_t OFFSET_SK_SEED = OFFSET_IDX+4;

constexpr size_t OFFSET_SK_PRF = OFFSET_SK_SEED+32;

constexpr size_t OFFSET_PUB_SEED = OFFSET_SK_PRF+32;

constexpr size_t OFFSET_ROOT = OFFSET_PUB_SEED+32;

TKEY XmssBase::getSKSeed()
{
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_SK_SEED, _sk.begin()+OFFSET_SK_SEED+32);
}

TKEY XmssBase::getSKPRF()
{
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_SK_PRF, _sk.begin()+OFFSET_SK_PRF+32);
}

TKEY XmssBase::getPKSeed()
{
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_PUB_SEED, _sk.begin()+OFFSET_PUB_SEED+32);
}

TKEY XmssBase::getRoot()
{
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_ROOT, _sk.begin()+OFFSET_ROOT+32);
}

uint32_t XmssBase::getIndex()
{
    return (_sk[0] << 24)+
            (_sk[1] << 16)+
            (_sk[2] << 8)+
            _sk[3];
}

uint32_t XmssBase::setIndex(uint32_t new_index)
{
    _sk[3] = static_cast<uint8_t>(new_index & 0xFF);
    new_index >>= 8;
    _sk[2] = static_cast<uint8_t>(new_index & 0xFF);
    new_index >>= 8;
    _sk[1] = static_cast<uint8_t>(new_index & 0xFF);
    new_index >>= 8;
    _sk[0] = static_cast<uint8_t>(new_index & 0xFF);

    return getIndex();
}

TKEY XmssBase::getSK()
{
    return _sk;
}

TKEY XmssBase::getPK()
{
    //    PK format
    //     3 QRL_DESCRIPTOR
    //    32 root address
    //    32 pub_seed

    // TODO: Improve and avoid copies / recalculation
    TKEY PK(getDescriptorBytes());
    auto root = getRoot();
    auto pubseed = getPKSeed();
    PK.insert(PK.end(), root.begin(), root.end());
    PK.insert(PK.end(), pubseed.begin(), pubseed.end());

    return PK;
}

TSEED XmssBase::getExtendedSeed()
{
    TKEY extendedSeed(getDescriptorBytes());
    extendedSeed.insert(extendedSeed.end(), _seed.begin(), _seed.end());
    return extendedSeed;
}

QRLDescriptor XmssBase::getDescriptor()
{
    return {
            _hashFunction,
            eSignatureType::XMSS,
            _height,
            _addrFormatType
    };
}

std::vector<uint8_t> XmssBase::getDescriptorBytes()
{
    return getDescriptor().getBytes();
}

std::vector<uint8_t> XmssBase::getAddress()
{
    return QRLHelper::getAddress(getPK());
}

bool XmssBase::verify(const TMESSAGE& message,
        const TSIGNATURE& signature,
        const TKEY& extended_pk)
{
    try
    {
        if (extended_pk.size()!=67) {
            throw std::invalid_argument("Invalid extended_pk size. It should be 67 bytes");
        }

        auto desc = QRLDescriptor::fromExtendedPK(extended_pk);

        if (desc.getSignatureType()!=eSignatureType::XMSS) {
            return false;
        }

        const auto height = static_cast<const uint8_t> (XmssBase::getHeightFromSigSize(signature.size()));

        if (height==0 || desc.getHeight()!=height) {
            return false;
        }

        auto hashFunction = desc.getHashFunction();

        xmss_params params{};
        const uint32_t k = 2;
        const uint32_t w = 16;
        const uint32_t n = 32;

        if (k>=height || (height-k)%2) {
            throw std::invalid_argument("For BDS traversal, H - K must be even, with H > K >= 2!");
        }

        xmss_set_params(&params, n, height, w, k);

        auto tmp = static_cast<TSIGNATURE>(signature);

        return xmss_Verifysig(hashFunction,
                &params.wots_par,
                static_cast<TMESSAGE>(message).data(),
                message.size(),
                tmp.data(),
                extended_pk.data()+QRLDescriptor::getSize(),
                height)==0;
    }
    catch(std::invalid_argument&)
    {
        return false;
    }
}
