#include "xmss-alt/algsxmss.h"
#include "xmssBasic.h"
#include <climits>
#include <iostream>
#include <utility>
#include <PicoSHA2/picosha2.h>
#include <crypto/secure_memory.h>
#include "qrlHelper.h"

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

//constexpr size_t SIGNATURE_BASE_SIZE  = 4+32+67*32;

// FIXME: Use a union for this
constexpr size_t OFFSET_IDX = 0;

constexpr size_t OFFSET_SK_SEED = OFFSET_IDX+4;

constexpr size_t OFFSET_SK_PRF = OFFSET_SK_SEED+32;

constexpr size_t OFFSET_PUB_SEED = OFFSET_SK_PRF+32;

constexpr size_t OFFSET_ROOT = OFFSET_PUB_SEED+32;

XmssBase::XmssBase(const TSEED& seed,
        uint8_t height,
        eHashFunction hashFunction,
        eAddrFormatType addrFormatType)
        : params{},
          _hashFunction(hashFunction),
          _addrFormatType(addrFormatType),
          _height(height)
{
    if (seed.size()!=XmssValidation::SEED_SIZE) {
        throw std::invalid_argument("Seed should be 48 bytes. Other values are not currently supported");
    }
    XmssValidation::height(height);
    XmssValidation::hashFunction(hashFunction);
    XmssValidation::addressFormat(addrFormatType);
    _seed = seed;
}

XmssBase::XmssBase(const TSEED& extended_seed)
    : params{},
      _hashFunction(eHashFunction::SHAKE_128),
      _addrFormatType(eAddrFormatType::SHA256_2X),
      _height(0)
{
    if (extended_seed.size()!=XmssValidation::EXTENDED_SEED_SIZE) {
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

#ifndef SWIG
XmssBase::XmssBase(const XmssBase& other)
    : params(other.params),
      _hashFunction(other._hashFunction),
      _addrFormatType(other._addrFormatType),
      _height(other._height),
      _sk(),
      _seed()
{
    TKEY replacement_sk(other._sk);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    TSEED replacement_seed(other._seed);
    qrllib::secure_memory::WipeGuard<uint8_t> seed_guard(replacement_seed);
    _sk.swap(replacement_sk);
    _seed.swap(replacement_seed);
}

XmssBase::XmssBase(XmssBase&& other) noexcept
    : params(other.params),
      _hashFunction(other._hashFunction),
      _addrFormatType(other._addrFormatType),
      _height(other._height),
      _sk(std::move(other._sk)),
      _seed(std::move(other._seed))
{
    qrllib::secure_memory::wipe(other._sk);
    qrllib::secure_memory::wipe(other._seed);
}

XmssBase& XmssBase::operator=(const XmssBase& other)
{
    if (this == &other) {
        return *this;
    }

    TKEY replacement_sk(other._sk);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    TSEED replacement_seed(other._seed);
    qrllib::secure_memory::WipeGuard<uint8_t> seed_guard(replacement_seed);

    qrllib::secure_memory::wipe_and_swap(_sk, replacement_sk);
    qrllib::secure_memory::wipe_and_swap(_seed, replacement_seed);
    params = other.params;
    _hashFunction = other._hashFunction;
    _addrFormatType = other._addrFormatType;
    _height = other._height;
    return *this;
}

XmssBase& XmssBase::operator=(XmssBase&& other) noexcept
{
    if (this == &other) {
        return *this;
    }

    qrllib::secure_memory::wipe(_sk);
    qrllib::secure_memory::wipe(_seed);
    _sk = std::move(other._sk);
    _seed = std::move(other._seed);
    params = other.params;
    _hashFunction = other._hashFunction;
    _addrFormatType = other._addrFormatType;
    _height = other._height;
    qrllib::secure_memory::wipe(other._sk);
    qrllib::secure_memory::wipe(other._seed);
    return *this;
}
#endif

XmssBase::~XmssBase()
{
    qrllib::secure_memory::wipe(_sk);
    qrllib::secure_memory::wipe(_seed);
}

uint32_t XmssBase::calculateSignatureBaseSize(uint32_t wotsParamW) {
  XmssValidation::wots(wotsParamW);
  wots_params wotsParams;
  wots_set_params(&wotsParams, 32, wotsParamW);
  return 4 + 32 + wotsParams.keysize;
}

uint32_t XmssBase::getSignatureSize(uint32_t wotsParamW)
{
    XmssValidation::height(_height);
    const uint32_t SIGNATURE_BASE_SIZE = calculateSignatureBaseSize(wotsParamW);
    // 4 + n + (len + h) * n)
    return static_cast<uint32_t>(SIGNATURE_BASE_SIZE+_height*32);
}

uint8_t XmssBase::getHeightFromSigSize(size_t sigSize, uint32_t wotsParamW)
{
    const uint32_t SIGNATURE_BASE_SIZE = calculateSignatureBaseSize(wotsParamW);
    if (sigSize < SIGNATURE_BASE_SIZE)
    {
        throw std::invalid_argument("Invalid signature size");
    }

    if ((sigSize-4)%32!=0) {
        throw std::invalid_argument("Invalid signature size");
    }

    const auto height = (sigSize - SIGNATURE_BASE_SIZE)/32;
    if (height > UINT8_MAX) {
        throw std::invalid_argument("Invalid signature size");
    }
    XmssValidation::height(static_cast<uint8_t>(height));

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

TKEY XmssBase::getSKSeed()
{
    validateBaseState();
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_SK_SEED, _sk.begin()+OFFSET_SK_SEED+32);
}

TKEY XmssBase::getSKPRF()
{
    validateBaseState();
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_SK_PRF, _sk.begin()+OFFSET_SK_PRF+32);
}

TKEY XmssBase::getPKSeed()
{
    validateBaseState();
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_PUB_SEED, _sk.begin()+OFFSET_PUB_SEED+32);
}

TKEY XmssBase::getRoot()
{
    validateBaseState();
// FIXME: Use a union for this
    return TKEY(_sk.begin()+OFFSET_ROOT, _sk.begin()+OFFSET_ROOT+32);
}

uint32_t XmssBase::getIndex()
{
    validateBaseState();
    return (_sk[0] << 24)+
           (_sk[1] << 16)+
           (_sk[2] << 8)+
            _sk[3];
}

uint32_t XmssBase::setIndex(uint32_t new_index)
{
    validateBaseState();
    const auto count = getNumberSignatures();
    const auto current = getIndex();
    if (new_index > count) {
        throw std::invalid_argument("index too high");
    }
    if (new_index < current) {
        throw std::invalid_argument("cannot rewind");
    }
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
    validateBaseState();
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
    validateBaseState();
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
        const TKEY& extended_pk,
        uint32_t wotsParamW)
{
    try
    {
        XmssValidation::wots(wotsParamW);
        if (extended_pk.size()!=XmssValidation::EXTENDED_PUBLIC_KEY_SIZE) {
            throw std::invalid_argument("Invalid extended_pk size. It should be 67 bytes");
        }
        const uint32_t SIGNATURE_BASE_SIZE = calculateSignatureBaseSize(wotsParamW);
        if (signature.size()>SIGNATURE_BASE_SIZE+XmssValidation::MAX_HEIGHT*32)
        {
            throw std::invalid_argument("invalid signature size");
        }

        auto desc = QRLDescriptor::fromExtendedPK(extended_pk);

        if (desc.getSignatureType()!=eSignatureType::XMSS) {
            return false;
        }

        const auto height = static_cast<const uint8_t> (XmssBase::getHeightFromSigSize(
                signature.size(), wotsParamW));

        if (desc.getHeight()!=height) {
            return false;
        }

        auto hashFunction = desc.getHashFunction();

        xmss_params params{};
        const uint32_t k = 2;
        const uint32_t w = wotsParamW;
        const uint32_t n = 32;

        if (k>=height || (height-k)%2) {
            throw std::invalid_argument("For BDS traversal, H - K must be even, with H > K >= 2!");
        }

        xmss_set_params(&params, n, height, w, k);
        if (!xmss_params_are_valid(&params)) {
            return false;
        }

        auto tmp = static_cast<TSIGNATURE>(signature);

        return xmss_Verifysig(hashFunction,
                &params.wots_par,
                message.data(),
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

void XmssBase::validateBaseState() const
{
    XmssValidation::height(_height);
    XmssValidation::hashFunction(_hashFunction);
    XmssValidation::addressFormat(_addrFormatType);
    if (_seed.size() != XmssValidation::SEED_SIZE ||
        _sk.size() != XmssValidation::SECRET_KEY_SIZE) {
        throw std::logic_error("Invalid XMSS secret state");
    }
    const uint32_t index = (static_cast<uint32_t>(_sk[0]) << 24) |
                           (static_cast<uint32_t>(_sk[1]) << 16) |
                           (static_cast<uint32_t>(_sk[2]) << 8) |
                           static_cast<uint32_t>(_sk[3]);
    if (index > XmssValidation::signatureCount(_height)) {
        throw std::logic_error("Invalid XMSS signing index");
    }
}
