// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_XMSS_H
#define QRLLIB_XMSS_H

#include <vector>
#include <string>
#include <stdexcept>
#include "xmssBase.h"

// This is unfortunately not fully supported by SWIG
// using TSIGNATURE = std::vector<unsigned char>;
// using TMESSAGE = std::vector<unsigned char>;

// TODO: Add a namespace

class XmssBasic : public ::XmssBase {
public:
    XmssBasic(const TSEED &seed,
              unsigned char height,
              eHashFunction hashFunction,
              eAddrFormatType addrFormatType);

    TSIGNATURE sign(const TMESSAGE &message) override;
};

#endif //QRLLIB_XMSS_H
