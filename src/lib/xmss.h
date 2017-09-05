// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLFAST_XMSS_H
#define QRLFAST_XMSS_H

#include<vector>

// This is unfortunately not fully supported by SWIG
// using TSIGNATURE = std::vector<unsigned char>;
// using TMESSAGE = std::vector<unsigned char>;

#define TSIGNATURE std::vector<unsigned char>
#define TMESSAGE std::vector<unsigned char>
#define TSEED std::vector<unsigned char>
#define TKEY std::vector<unsigned char>

class Xmss {
public:
    // TODO: Fix constness / passing by copy, this requires changes in the underlying lib
    Xmss(const TSEED &seed, unsigned char height);

    TSIGNATURE sign(const TMESSAGE &message);

    bool verify(const TMESSAGE &message,
                const TSIGNATURE &signature,
                const TKEY &pk,
                unsigned char height);

    int getHeight() {  return _height; }
    TKEY getPK() {  return _pk; }
    TKEY getSK() {  return _sk; }
    TSEED getSeed() {  return _seed; }
    uint32_t getSignatureSize();
    uint32_t getSecretKeySize();
private:

    unsigned char _height;

    TKEY _pk;
    TKEY _sk;
    TSEED _seed;
};

#endif //QRLFAST_XMSS_H
