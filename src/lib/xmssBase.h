#ifndef QRLLIB_XMSSBASE_H
#define QRLLIB_XMSSBASE_H

#include <string>
#include <vector>

#define TSIGNATURE std::vector<unsigned char>
#define TMESSAGE std::vector<unsigned char>
#define TSEED std::vector<unsigned char>
#define TKEY std::vector<unsigned char>

class XmssBase {
public:
    // TODO: Fix constness / passing by value, etc. This might require changes in the underlying lib
    XmssBase(const TSEED &seed, unsigned char height);
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
    virtual unsigned int setIndex(unsigned int new_index);

    unsigned int getSignatureSize();
    unsigned int getSecretKeySize();
    unsigned int getPublicKeySize();

protected:
    unsigned char _height;
    TKEY _sk;
    TSEED _seed;
};

#include <vector>

#endif //QRLLIB_XMSSBASE_H
