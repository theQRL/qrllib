#ifndef QRLLIB_XMSSBASE_H
#define QRLLIB_XMSSBASE_H

#include <string>
#include <vector>
#include "xmss-alt/xmss_params.h"

#define TSIGNATURE std::vector<uint8_t>
#define TMESSAGE std::vector<uint8_t>
#define TSEED std::vector<uint8_t>
#define TKEY std::vector<uint8_t>

class XmssBase {
public:
    // TODO: Fix constness / passing by value, etc. This might require changes in the underlying lib
    XmssBase(const TSEED &seed, uint8_t height);
    virtual ~XmssBase()=default;

    virtual TSIGNATURE sign(const TMESSAGE &message) = 0;

    // TODO: Differentiate between XMSS and WOTS+ keys
    TKEY getSK() {  return _sk; }
    TKEY getPK();
    int getHeight() {  return _height; }
    TSEED getSeed() {  return _seed; }

    // TODO: Maybe improve this using a union down into the original code?
    TKEY getRoot();
    TKEY getPKSeed();
    TKEY getSKSeed();
    TKEY getSKPRF();

    std::string getAddress(const std::string &prefix);

    unsigned int getIndex();
    virtual unsigned int setIndex(uint32_t new_index);

    unsigned int getSignatureSize();
    static uint8_t getHeightFromSigSize(size_t sigSize);

    unsigned int getSecretKeySize();
    unsigned int getPublicKeySize();

    static bool verify(const TMESSAGE &message,
                       const TSIGNATURE &signature,
                       const TKEY &pk);

protected:
    xmss_params params;

    unsigned char _height;
    TKEY _sk;
    TSEED _seed;
};

#include <vector>

#endif //QRLLIB_XMSSBASE_H
