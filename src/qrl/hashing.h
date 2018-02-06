// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_HASHING_H
#define QRLLIB_HASHING_H

#include <vector>
#include <cstddef>

std::vector<unsigned char> sha2_256(std::vector<unsigned char> input);

std::vector<unsigned char> sha2_256_n(std::vector<unsigned char> input, size_t count);

std::vector<unsigned char> shake128(size_t hash_size, std::vector<unsigned char> input);

std::vector<unsigned char> shake256(size_t hash_size, std::vector<unsigned char> data);

#endif // QRLLIB_HASHING_H
