// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "hashing.h"
#include "xmssBase.h"
#include <crypto/secure_memory.h>
#include <xmss-alt/hash.h>
#include <sstream>
#include <iomanip>
#include <xmss-alt/fips202.h>
#include <PicoSHA2/picosha2.h>
#include <iostream>
#include <stdexcept>
#include <unordered_map>

std::vector<unsigned char> shake128(size_t hash_size, std::vector<unsigned char> input) {
    qrllib::secure_memory::WipeGuard<unsigned char> input_guard(input);
    std::vector<unsigned char> hashed_output(hash_size, 0);
    qrllib::secure_memory::WipeGuard<unsigned char> output_guard(hashed_output);
    shake128(hashed_output.data(), hash_size, input.data(), input.size());
    output_guard.release();
    return hashed_output;
}

std::vector<unsigned char> shake256(size_t hash_size, std::vector<unsigned char> input) {
    qrllib::secure_memory::WipeGuard<unsigned char> input_guard(input);
    std::vector<unsigned char> hashed_output(hash_size, 0);
    qrllib::secure_memory::WipeGuard<unsigned char> output_guard(hashed_output);
    shake256(hashed_output.data(), hash_size, input.data(), input.size());
    output_guard.release();
    return hashed_output;
}

std::vector<unsigned char> sha2_256(std::vector<unsigned char> input) {
    qrllib::secure_memory::WipeGuard<unsigned char> input_guard(input);
    std::vector<unsigned char> hashed_output(32, 0);
    qrllib::secure_memory::WipeGuard<unsigned char> output_guard(hashed_output);
    if (sha2_256_secure(hashed_output.data(), input.data(), input.size()) != 0) {
        throw std::runtime_error("SHA2-256 input is too large");
    }
    output_guard.release();
    return hashed_output;
}

std::vector<unsigned char> sha2_256_n(std::vector<unsigned char> input, size_t count) {
    qrllib::secure_memory::WipeGuard<unsigned char> input_guard(input);
    if (count == 0) {
        throw std::invalid_argument("Invalid count. It should be > 0");
    }

    std::vector<unsigned char> hashed_output(32, 0);
    qrllib::secure_memory::WipeGuard<unsigned char> output_guard(hashed_output);

    if (sha2_256_secure(hashed_output.data(), input.data(), input.size()) != 0) {
        throw std::runtime_error("SHA2-256 input is too large");
    }
    for (size_t i = 1; i < count; i++) {
        if (sha2_256_secure(hashed_output.data(), hashed_output.data(),
                            hashed_output.size()) != 0) {
            throw std::runtime_error("SHA2-256 iteration failed");
        }
    }

    output_guard.release();
    return hashed_output;
}
