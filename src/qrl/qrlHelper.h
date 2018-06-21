// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_QRLHELPER_H
#define QRLLIB_QRLHELPER_H

#include <vector>
#include <cstdint>
#include <qrlDescriptor.h>
#include <PicoSHA2/picosha2.h>
#include <stdexcept>
#include "misc.h"

class QRLHelper {
public:
    QRLHelper() = default;

    static std::vector<uint8_t> getAddress(const std::vector<uint8_t>& extended_pk)
    {
        auto descr = QRLDescriptor::fromExtendedPK(extended_pk);

        if (descr.getAddrFormatType()!=eAddrFormatType::SHA256_2X) {
            throw std::invalid_argument("Address format type not supported");
        }

        const auto descrBytes = descr.getBytes();
        auto address = descrBytes;

        std::vector<uint8_t> hashed_key(ADDRESS_HASH_SIZE, 0);
        picosha2::hash256(extended_pk.begin(), extended_pk.end(), hashed_key.begin(), hashed_key.end());
        address.insert(address.end(), hashed_key.cbegin(), hashed_key.cend());

        std::vector<uint8_t> hashed_key2(ADDRESS_HASH_SIZE, 0);
        picosha2::hash256(address.begin(), address.end(), hashed_key2.begin(), hashed_key2.end());
        address.insert(address.end(), hashed_key2.cend()-4, hashed_key2.cend());

        return address;
    }

    static bool addressIsValid(const std::vector<uint8_t>& address)
    {
        try {
            if (address.size()!=(QRLDescriptor::getSize()+ADDRESS_HASH_SIZE+4))
                return false;

            auto descr = QRLDescriptor::fromBytes(
                    std::vector<uint8_t>(
                            address.cbegin(),
                            address.cbegin()+QRLDescriptor::getSize()));

            if (descr.getAddrFormatType()!=eAddrFormatType::SHA256_2X) {
                return false;
            }

            std::vector<uint8_t> hashed_key2(ADDRESS_HASH_SIZE, 0);

            picosha2::hash256(address.cbegin(), address.cbegin()+QRLDescriptor::getSize()+ADDRESS_HASH_SIZE,
                    hashed_key2.begin(), hashed_key2.end());

            return address[35]==hashed_key2[28] &&
                    address[36]==hashed_key2[29] &&
                    address[37]==hashed_key2[30] &&
                    address[38]==hashed_key2[31];
        }
        catch (...) {
            return false;
        }
    }
};

#endif
