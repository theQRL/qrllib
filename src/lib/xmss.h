// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_XMSS_H
#define QRLLIB_XMSS_H

#include <vector>
#include <string>
#include "xmssBase.h"

// This is unfortunately not fully supported by SWIG
// using TSIGNATURE = std::vector<unsigned char>;
// using TMESSAGE = std::vector<unsigned char>;

// TODO: Add a namespace

class Xmss : public ::XmssBase {
public:
    // TODO: Fix constness / passing by copy, this requires changes in the underlying lib
    Xmss(const TSEED &seed, unsigned char height);

    TSIGNATURE sign(const TMESSAGE &message) override;

    static bool verify(const TMESSAGE &message,
                       const TSIGNATURE &signature,
                       const TKEY &pk,
                       unsigned char height);
};

#endif //QRLLIB_XMSS_H
