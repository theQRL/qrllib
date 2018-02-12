#include "xmss-alt/algsxmss.h"
#include "xmssBasic.h"
#include <iostream>
#include <PicoSHA2/picosha2.h>
#include "misc.h"

XmssBase::XmssBase(const TSEED &seed,
                   uint8_t height,
                   eHashFunction hashFunction) throw(std::invalid_argument)
        : _seed(seed), _height(height), _hashFunction(hashFunction) {
    if (seed.size() != 48) {
        throw std::invalid_argument("Seed should be 48 bytes. Other values are not currently supported");
    }
}

uint32_t XmssBase::getSignatureSize() {
    // 4 + n + (len + h) * n)
    // FIXME: There could be consistency problems due to changes in len
    return static_cast<uint32_t>(4 + 32 + 67 * 32 + _height * 32);
}

uint8_t XmssBase::getHeightFromSigSize(size_t sigSize) {
    // FIXME: Clean this up and consider len
    return static_cast<uint8_t>((sigSize - 4 - 32 - 67 * 32) / 32);
}

uint32_t XmssBase::getPublicKeySize() {
    return 64;
}

uint32_t XmssBase::getSecretKeySize() {
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

// FIXME: Use a union for this
constexpr size_t OFFSET_IDX = 0;
constexpr size_t OFFSET_SK_SEED = OFFSET_IDX + 4;
constexpr size_t OFFSET_SK_PRF = OFFSET_SK_SEED + 32;
constexpr size_t OFFSET_PUB_SEED = OFFSET_SK_PRF + 32;
constexpr size_t OFFSET_ROOT = OFFSET_PUB_SEED + 32;

TKEY XmssBase::getSKSeed() {
// FIXME: Use a union for this
    return TKEY(_sk.begin() + OFFSET_SK_SEED, _sk.begin() + OFFSET_SK_SEED + 32);
}

TKEY XmssBase::getSKPRF() {
// FIXME: Use a union for this
    return TKEY(_sk.begin() + OFFSET_SK_PRF, _sk.begin() + OFFSET_SK_PRF + 32);
}

TKEY XmssBase::getPKSeed() {
// FIXME: Use a union for this
    return TKEY(_sk.begin() + OFFSET_PUB_SEED, _sk.begin() + OFFSET_PUB_SEED + 32);
}

TKEY XmssBase::getRoot() {
// FIXME: Use a union for this
    return TKEY(_sk.begin() + OFFSET_ROOT, _sk.begin() + OFFSET_ROOT + 32);
}

uint32_t XmssBase::getIndex() {
    return (_sk[0] << 24) +
           (_sk[1] << 16) +
           (_sk[2] << 8) +
           _sk[3];
}

uint32_t XmssBase::setIndex(uint32_t new_index) {
    _sk[3] = static_cast<uint8_t>(new_index & 0xFF);
    new_index >>= 8;
    _sk[2] = static_cast<uint8_t>(new_index & 0xFF);
    new_index >>= 8;
    _sk[1] = static_cast<uint8_t>(new_index & 0xFF);
    new_index >>= 8;
    _sk[0] = static_cast<uint8_t>(new_index & 0xFF);

    return getIndex();
}

TKEY XmssBase::getSK() {
    return _sk;
}

TKEY XmssBase::getPK() {
    //    PK format
    //    32 root address
    //    32 pub_seed

    // TODO: Improve and avoid copies / recalculation
    TKEY PK(getRoot());
    auto pubseed = getPKSeed();

    PK.insert(PK.end(), pubseed.begin(), pubseed.end());

    return PK;
}

std::vector<uint8_t> XmssBase::getDescriptor()
{
    // descriptor
    //  0.. 3   hash function    [ SHA2-256, SHA3, .. ]
    //  4.. 7   signature scheme [ XMSS, XMSS^MT, .. ]
    //  8..11   params:  i.e. Height / 2
    // 12..15   params2: reserved

    const uint8_t hash_type = _hashFunction;
    const uint8_t sig_type = 0;
    const uint8_t param1 = _height >> 1;
    const uint8_t param2 = 0;

    std::vector<uint8_t> descr{
        static_cast<uint8_t>(sig_type << 4 | hash_type & 0x0F),
        static_cast<uint8_t>(param2 << 4 | param1 & 0x0F),
    };

    return descr;
}

std::vector<uint8_t> XmssBase::getAddress() {
    std::vector<uint8_t> key = getPK();

    TKEY hashed_key(ADDRESS_HASH_SIZE+2, 0);
    TKEY hashed_key2(ADDRESS_HASH_SIZE, 0);

    auto descriptor = getDescriptor();
    hashed_key[0] = descriptor[0];
    hashed_key[1] = descriptor[1];

    picosha2::hash256(key.begin(), key.end(), hashed_key.begin()+2, hashed_key.end());
    picosha2::hash256(hashed_key.begin(), hashed_key.end(), hashed_key2.begin(), hashed_key2.end());

    hashed_key.insert(hashed_key.end(), hashed_key2.cend() - 4, hashed_key2.cend());

    return hashed_key;
}

bool XmssBase::verify(const TMESSAGE &message,
                      const TSIGNATURE &signature,
                      const TKEY &pk,
                      eHashFunction hashFunction) throw(std::invalid_argument) {
    const auto height = static_cast<const uint8_t>(XmssBase::getHeightFromSigSize(signature.size()));

    xmss_params params{};
    const uint32_t k = 2;
    const uint32_t w = 16;
    const uint32_t n = 32;

    if (k >= height || (height - k) % 2) {
        throw std::invalid_argument("For BDS traversal, H - K must be even, with H > K >= 2!");
    }

    xmss_set_params(&params, n, height, w, k);

    auto tmp = static_cast<TSIGNATURE>(signature);
    return xmss_Verifysig(hashFunction,
                          &params.wots_par,
                          static_cast<TMESSAGE>(message).data(),
                          message.size(),
                          tmp.data(),
                          pk.data(),
                          height) == 0;
}
