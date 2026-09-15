// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_XMSSVALIDATION_H
#define QRLLIB_XMSSVALIDATION_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include <xmss-alt/eHashFunctions.h>
#include "qrlAddressFormat.h"

namespace XmssValidation {

constexpr std::size_t SEED_SIZE = 48;
constexpr std::size_t EXTENDED_SEED_SIZE = 51;
constexpr std::size_t SECRET_KEY_SIZE = 132;
constexpr std::size_t EXTENDED_PUBLIC_KEY_SIZE = 67;
constexpr uint8_t MIN_HEIGHT = 4;
constexpr uint8_t MAX_HEIGHT = 30;
constexpr uint32_t BDS_K = 2;
constexpr uint32_t N = 32;

void hashFunction(eHashFunction value);
void addressFormat(eAddrFormatType value);
void height(uint8_t value);
void wots(uint32_t value);
void descriptorBytes(const std::vector<uint8_t>& bytes);

uint32_t signatureCount(uint8_t height);

}  // namespace XmssValidation

#endif  // QRLLIB_XMSSVALIDATION_H
