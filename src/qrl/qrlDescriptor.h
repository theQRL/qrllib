// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_SIGNSDESCR_H
#define QRLLIB_SIGNSDESCR_H

#include <vector>
#include <cstdint>
#include "xmss-alt/eHashFunctions.h"

enum eSignatureType {
    XMSS = 0,
};

class QRLDescriptor {
public:
    QRLDescriptor(eHashFunction hashFunction,
                  eSignatureType signatureType,
                  uint8_t height,
                  uint8_t params2 = 0) :
            _hashFunction(hashFunction),
            _signatureType(signatureType),
            _height(height),
            _params2(params2) {}

    eHashFunction getHashFunction() { return _hashFunction; }

    eSignatureType getSignatureType() { return _signatureType; }

    uint8_t getHeight() { return _height; }

    uint8_t getParams2() { return _params2; }

    static QRLDescriptor fromBytes(uint8_t byte0, uint8_t byte1) {
        auto hashFunction = static_cast<eHashFunction>(byte0 & 0x0F);
        auto signatureType = static_cast<eSignatureType>( (byte0 >> 4) & 0xF0);
        auto height = static_cast<uint8_t>( (byte1 & 0x0F) << 1 );
        auto params2 = static_cast<uint8_t>( (byte1 & 0xF0) >> 4 );

        return {hashFunction, signatureType, height, params2};
    }

    static uint8_t getSize()
    {
        return 3;
    }

    std::vector<uint8_t> getBytes() {
        // descriptor
        //  0.. 3   hash function    [ SHA2-256, SHA3, .. ]
        //  4.. 7   signature scheme [ XMSS, XMSS^MT, .. ]
        //  8..11   params:  i.e. Height / 2
        // 12..15   params2: reserved
        // 16..23   params3: reserved

        std::vector<uint8_t> descr{
                static_cast<uint8_t>( (_signatureType << 4) | (_hashFunction & 0x0F)),
                static_cast<uint8_t>( (_params2 << 4) | ((_height >> 1) & 0x0F)),
                0
        };

        return descr;
    }

private:
    eHashFunction _hashFunction;
    eSignatureType _signatureType;
    uint8_t _height;
    uint8_t _params2;
};


#endif
