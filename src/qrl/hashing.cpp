// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "hashing.h"
#include "xmssBase.h"
#include <sstream>
#include <iomanip>
#include <dilithium/ref/fips202.h>
#include <PicoSHA2/picosha2.h>
#include <iostream>
#include <unordered_map>

std::vector<unsigned char> shake128(size_t hash_size, std::vector<unsigned char> input) {
    std::vector<unsigned char> hashed_output(hash_size, 0);
    shake128(hashed_output.data(), hash_size, input.data(), input.size());
    return hashed_output;
}

std::vector<unsigned char> shake256(size_t hash_size, std::vector<unsigned char> input) {
    std::vector<unsigned char> hashed_output(hash_size, 0);
    shake256(hashed_output.data(), hash_size, input.data(), input.size());
    return hashed_output;
}

std::vector<unsigned char> sha2_256(std::vector<unsigned char> input) {
    std::vector<unsigned char> hashed_output(32, 0);
    picosha2::hash256(input.begin(), input.end(), hashed_output.begin(), hashed_output.end());
    return hashed_output;
}

std::vector<unsigned char> sha2_256_n(std::vector<unsigned char> input, size_t count) {
    if (count == 0) {
        throw std::invalid_argument("Invalid count. It should be > 0");
    }

    std::vector<unsigned char> hashed_output(32, 0);

    picosha2::hash256(input.begin(), input.end(), hashed_output.begin(), hashed_output.end());
    for (size_t i = 1; i < count; i++) {
        picosha2::hash256(hashed_output.begin(), hashed_output.end(), hashed_output.begin(), hashed_output.end());
    }

    return hashed_output;
}
