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
    QRLHelper()= default;

    static std::vector<uint8_t> getAddress(const std::vector<uint8_t>&pk)
    {
        auto descr = QRLHelper::extractDescriptor(pk);
        auto address = descr.getBytes();

        std::vector<uint8_t> hashed_key(ADDRESS_HASH_SIZE, 0);
        picosha2::hash256(pk.begin(), pk.end(), hashed_key.begin(), hashed_key.end());
        address.insert(address.end(), hashed_key.cbegin(), hashed_key.cend());

        std::vector<uint8_t> hashed_key2(ADDRESS_HASH_SIZE, 0);
        picosha2::hash256(hashed_key.begin(), hashed_key.end(), hashed_key2.begin(), hashed_key2.end());
        address.insert(address.end(), hashed_key2.cend() - 4, hashed_key2.cend());

        return address;
    }

    static QRLDescriptor extractDescriptor(const std::vector<uint8_t>&pk) throw(std::invalid_argument)
    {
        if (pk.size()<2) {
            throw std::invalid_argument("invalid pk size");
        }
        return QRLDescriptor::fromBytes(pk[0], pk[1]);
    }
};


#endif
