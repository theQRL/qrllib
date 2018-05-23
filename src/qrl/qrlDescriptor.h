// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_SIGNSDESCR_H
#define QRLLIB_SIGNSDESCR_H

#include <vector>
#include <cstdint>
#include <stdexcept>

#include "xmss-alt/eHashFunctions.h"
#include "qrlAddressFormat.h"

enum eSignatureType {
  XMSS = 0,
};

class QRLDescriptor {
public:
    QRLDescriptor(eHashFunction hashFunction,
            eSignatureType signatureType,
            uint8_t height,
            eAddrFormatType addrFormatType)
            :
            _hashFunction(hashFunction),
            _signatureType(signatureType),
            _height(height),
            _addrFormatType(addrFormatType) { }

    eHashFunction getHashFunction() { return _hashFunction; }

    eSignatureType getSignatureType() { return _signatureType; }

    uint8_t getHeight() { return _height; }

    eAddrFormatType getAddrFormatType() { return _addrFormatType; }

    static QRLDescriptor fromExtendedSeed(std::vector<uint8_t> extended_seed)
    {
        if (extended_seed.size()!=51) {
            throw std::invalid_argument("Extended seed should be 51 bytes");
        }

        return QRLDescriptor::fromBytes(
                std::vector<uint8_t>(
                        extended_seed.cbegin(),
                        extended_seed.cbegin()+QRLDescriptor::getSize()));
    }

    static QRLDescriptor fromExtendedPK(const std::vector<uint8_t>& extended_pk)
    {
        if (extended_pk.size()!=67) {
            throw std::invalid_argument("Invalid extended_pk size. It should be 67 bytes");
        }

        return QRLDescriptor::fromBytes(
                std::vector<uint8_t>(
                        extended_pk.cbegin(),
                        extended_pk.cbegin()+QRLDescriptor::getSize()));
    }

    static QRLDescriptor fromBytes(std::vector<uint8_t> bytes)
    {
        if (bytes.size()!=3) {
            throw std::invalid_argument("Descriptor size should be 3 bytes");
        }

        auto hashFunction = static_cast<eHashFunction>(bytes[0] & 0x0F);
        auto signatureType = static_cast<eSignatureType>((bytes[0] >> 4) & 0xF0);
        auto height = static_cast<uint8_t>((bytes[1] & 0x0F) << 1 );
        auto addrFormatType = static_cast<eAddrFormatType>((bytes[1] & 0xF0) >> 4 );

        return {hashFunction, signatureType, height, addrFormatType};
    }

    static uint8_t getSize()
    {
        return 3;
    }

    std::vector<uint8_t> getBytes()
    {
        // descriptor
        //  0.. 3   hash function    [ SHA2-256, SHA3, .. ]
        //  4.. 7   signature scheme [ XMSS, XMSS^MT, .. ]
        //  8..11   params:  i.e. Height / 2
        // 12..15   params2: reserved
        // 16..23   params3: reserved

        std::vector<uint8_t> descr{
                static_cast<uint8_t>((_signatureType << 4) | (_hashFunction & 0x0F)),
                static_cast<uint8_t>((_addrFormatType << 4) | ((_height >> 1) & 0x0F)),
                0
        };

        return descr;
    }

private:
    eHashFunction _hashFunction;
    eSignatureType _signatureType;
    uint8_t _height;
    eAddrFormatType _addrFormatType;
};

#endif
