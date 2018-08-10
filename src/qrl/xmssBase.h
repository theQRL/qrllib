#ifndef QRLLIB_XMSSBASE_H
#define QRLLIB_XMSSBASE_H

#include <string>
#include <vector>
#include <stdexcept>
#include <xmss-alt/eHashFunctions.h>
#include <xmss-alt/xmss_params.h>
#include "qrlDescriptor.h"

#define TSIGNATURE std::vector<uint8_t>
#define TMESSAGE std::vector<uint8_t>
#define TSEED std::vector<uint8_t>
#define TKEY std::vector<uint8_t>

// TODO: Use a union? to operate on partial fields
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

class XmssBase {
public:
    XmssBase(const TSEED &seed,
             uint8_t height,
             eHashFunction hashFunction,
             eAddrFormatType formatType);

    XmssBase(const TSEED &extended_seed);

    virtual ~XmssBase() = default;

    virtual TSIGNATURE sign(const TMESSAGE &message) = 0;

    static bool verify(const TMESSAGE &message,
                       const TSIGNATURE &signature,
                       const TKEY &pk);

    // TODO: Differentiate between XMSS and WOTS+ keys
    TKEY getSK();

    TKEY getPK();

    QRLDescriptor getDescriptor();
    std::vector<uint8_t> getDescriptorBytes();

    uint8_t getHeight() { return _height; }

    TSEED getSeed() { return _seed; }

    TSEED getExtendedSeed();

    // TODO: Maybe improve this using a union down into the original code?
    TKEY getRoot();

    TKEY getPKSeed();

    TKEY getSKSeed();

    TKEY getSKPRF();

    std::vector<uint8_t> getAddress();

    uint32_t getNumberSignatures() { return ((uint32_t) 1) << _height; }

    uint32_t getRemainingSignatures() { return getNumberSignatures() - getIndex(); }

    unsigned int getIndex();

    virtual unsigned int setIndex(uint32_t new_index);

    unsigned int getSignatureSize();

    static uint8_t getHeightFromSigSize(size_t sigSize);

    unsigned int getSecretKeySize();

    unsigned int getPublicKeySize();

protected:
    xmss_params params;

    eHashFunction _hashFunction;
    eAddrFormatType _addrFormatType;
    uint8_t _height;
    TKEY _sk;
    TSEED _seed;
};

#include <vector>

#endif //QRLLIB_XMSSBASE_H
