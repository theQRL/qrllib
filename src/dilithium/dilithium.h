// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_DILITHIUM_H
#define QRLLIB_DILITHIUM_H

#include <string>
#include <vector>
#include <dilithium/ref/api.h>
#include <dilithium/ref/randombytes.h>

class Dilithium {
public:
    Dilithium();

    Dilithium(const std::vector<uint8_t> &pk, const std::vector<uint8_t> &sk);

    virtual ~Dilithium() = default;

    std::vector<uint8_t> sign(const std::vector<uint8_t> &message);

    std::vector<uint8_t> getSK() { return _sk; }

    std::vector<uint8_t> getPK() { return _pk; }

    unsigned int getSecretKeySize() { return CRYPTO_SECRETKEYBYTES; }

    unsigned int getPublicKeySize() { return CRYPTO_PUBLICKEYBYTES; }

    static bool sign_open(std::vector<uint8_t> &message_output,
                          const std::vector<uint8_t> &message_signed,
                          const std::vector<uint8_t> &pk);

    static std::vector<uint8_t> extract_message(std::vector<uint8_t> &message_output);

    static std::vector<uint8_t> extract_signature(std::vector<uint8_t> &message_output);

protected:
    std::vector<uint8_t> _pk;
    std::vector<uint8_t> _sk;
};

#endif //QRLLIB_DILITHIUM_H
