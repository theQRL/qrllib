// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include <crypto/secure_memory.h>
#include "dilithium.h"

static_assert(std::numeric_limits<std::size_t>::digits <=
              std::numeric_limits<unsigned long long>::digits,
              "Dilithium backend length cannot represent size_t");

namespace {

void wipe_vector_storage(std::vector<uint8_t>& value) noexcept
{
    // Only live elements may be written. Every qrllib-controlled shrink and
    // clear calls this while the discarded bytes are still constructed.
    qrllib::secure_memory::wipe(value);
}

void wipe_and_clear(std::vector<uint8_t>& value) noexcept
{
    wipe_vector_storage(value);
    value.clear();
}

}  // namespace

Dilithium::Dilithium()
{
    std::vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES, 0);
    std::vector<uint8_t> sk(CRYPTO_SECRETKEYBYTES, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(sk);

    if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
        throw std::runtime_error("Dilithium key generation failed");
    }

    _pk.swap(pk);
    _sk.swap(sk);
}

Dilithium::Dilithium(const std::vector<uint8_t> &pk, const std::vector<uint8_t> &sk)
{
    if (pk.size() != CRYPTO_PUBLICKEYBYTES) {
        throw std::invalid_argument("Dilithium public key has an invalid size");
    }
    if (sk.size() != CRYPTO_SECRETKEYBYTES) {
        throw std::invalid_argument("Dilithium secret key has an invalid size");
    }

    std::vector<uint8_t> replacement_pk(pk);
    std::vector<uint8_t> replacement_sk(sk.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    std::copy(sk.begin(), sk.end(), replacement_sk.begin());

    _pk.swap(replacement_pk);
    _sk.swap(replacement_sk);
}

Dilithium::Dilithium(const Dilithium& other)
{
    std::vector<uint8_t> replacement_pk(other._pk);
    std::vector<uint8_t> replacement_sk(other._sk.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    std::copy(other._sk.begin(), other._sk.end(), replacement_sk.begin());

    _pk.swap(replacement_pk);
    _sk.swap(replacement_sk);
}

Dilithium& Dilithium::operator=(const Dilithium& other)
{
    if (this == &other) {
        return *this;
    }

    std::vector<uint8_t> replacement_pk(other._pk);
    std::vector<uint8_t> replacement_sk(other._sk.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    std::copy(other._sk.begin(), other._sk.end(), replacement_sk.begin());

    _pk.swap(replacement_pk);
    wipe_vector_storage(_sk);
    _sk.swap(replacement_sk);
    return *this;
}

Dilithium::~Dilithium()
{
    wipe_vector_storage(_sk);
}

std::vector<uint8_t> Dilithium::sign(const std::vector<uint8_t> &message)
{
    if (_sk.size() != CRYPTO_SECRETKEYBYTES) {
        throw std::invalid_argument("Dilithium secret key has an invalid size");
    }

    std::vector<uint8_t> message_signed;
    if (message.size() > message_signed.max_size() - CRYPTO_BYTES) {
        throw std::length_error("Dilithium message is too large");
    }

    const auto expected_size = message.size() + CRYPTO_BYTES;
    message_signed.resize(expected_size, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> signed_guard(message_signed);
    unsigned long long message_signed_size = 0;

    const auto status = crypto_sign(message_signed.data(),
                                    &message_signed_size,
                                    message.data(),
                                    static_cast<unsigned long long>(message.size()),
                                    _sk.data());
    if (status != 0 ||
        message_signed_size != static_cast<unsigned long long>(expected_size)) {
        throw std::runtime_error("Dilithium signing failed");
    }

    signed_guard.release();
    return message_signed;

// TODO: Leon, return only signature?
//    return std::vector<unsigned char>(message_signed.begin()+message.size(),
//                                      message_signed.end());
}

bool Dilithium::sign_open(std::vector<uint8_t> &message_output,
                          const std::vector<uint8_t> &message_signed,
                          const std::vector<uint8_t> &pk)
{
    if (pk.size() != CRYPTO_PUBLICKEYBYTES ||
        message_signed.size() < CRYPTO_BYTES) {
        wipe_and_clear(message_output);
        return false;
    }

    std::vector<uint8_t> signed_copy;
    qrllib::secure_memory::WipeGuard<uint8_t> signed_copy_guard(signed_copy);
    const std::vector<uint8_t>* signed_input = &message_signed;
    if (&message_output == &message_signed) {
        signed_copy.resize(message_signed.size(), 0);
        std::copy(message_signed.begin(), message_signed.end(), signed_copy.begin());
        signed_input = &signed_copy;
    }

    std::vector<uint8_t> pk_copy;
    const std::vector<uint8_t>* public_key = &pk;
    if (&message_output == &pk) {
        pk_copy = pk;
        public_key = &pk_copy;
    }

    wipe_and_clear(message_output);

    std::vector<uint8_t> recovered(signed_input->size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> recovered_guard(recovered);
    unsigned long long recovered_size = 0;
    const auto status = crypto_sign_open(recovered.data(),
                                         &recovered_size,
                                         signed_input->data(),
                                         static_cast<unsigned long long>(signed_input->size()),
                                         public_key->data());
    const auto expected_size = signed_input->size() - CRYPTO_BYTES;
    if (status != 0 ||
        recovered_size != static_cast<unsigned long long>(expected_size)) {
        return false;
    }

    if (expected_size < recovered.size()) {
        qrllib::secure_memory::secure_zero(recovered.data() + expected_size,
                                           recovered.size() - expected_size);
    }
    recovered.resize(expected_size);
    message_output.swap(recovered);
    return true;
}

std::vector<uint8_t> Dilithium::extract_message(std::vector<uint8_t> &message_output)
{
    if (message_output.size() < CRYPTO_BYTES) {
        return {};
    }
    return std::vector<uint8_t>(message_output.begin() + CRYPTO_BYTES, message_output.end());
}

std::vector<uint8_t> Dilithium::extract_signature(std::vector<uint8_t> &message_output)
{
    if (message_output.size() < CRYPTO_BYTES) {
        return {};
    }
    return std::vector<uint8_t>(message_output.begin(), message_output.begin() + CRYPTO_BYTES);
}
