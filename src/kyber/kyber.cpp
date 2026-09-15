// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <crypto/secure_memory.h>
#include "kyber.h"

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

Kyber::Kyber(const std::vector<uint8_t> &pk,
             const std::vector<uint8_t> &sk)
{
    if (pk.size()!=KYBER_PUBLICKEYBYTES)
    {
        throw std::invalid_argument("pk. Invalid size");
    }

    if (sk.size()!=KYBER_SECRETKEYBYTES)
    {
        throw std::invalid_argument("sk. Invalid size");
    }

    std::vector<uint8_t> replacement_pk(pk);
    std::vector<uint8_t> replacement_sk(sk.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    std::copy(sk.begin(), sk.end(), replacement_sk.begin());

    _pk.swap(replacement_pk);
    _sk.swap(replacement_sk);
}

Kyber::Kyber()
{
    std::vector<uint8_t> pk(KYBER_PUBLICKEYBYTES, 0);
    std::vector<uint8_t> sk(KYBER_SECRETKEYBYTES, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(sk);

    if (crypto_kem_keypair(pk.data(), sk.data()) != 0) {
        throw std::runtime_error("Kyber key generation failed");
    }

    _pk.swap(pk);
    _sk.swap(sk);
}

Kyber::Kyber(const Kyber& other)
{
    std::vector<uint8_t> replacement_pk(other._pk);
    std::vector<uint8_t> replacement_sk(other._sk.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    std::copy(other._sk.begin(), other._sk.end(), replacement_sk.begin());

    std::vector<uint8_t> replacement_key(other._key.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> key_guard(replacement_key);
    std::copy(other._key.begin(), other._key.end(), replacement_key.begin());
    std::vector<uint8_t> replacement_ct(other._ct);

    _pk.swap(replacement_pk);
    _sk.swap(replacement_sk);
    _key.swap(replacement_key);
    _ct.swap(replacement_ct);
}

Kyber& Kyber::operator=(const Kyber& other)
{
    if (this == &other) {
        return *this;
    }

    std::vector<uint8_t> replacement_pk(other._pk);
    std::vector<uint8_t> replacement_sk(other._sk.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(replacement_sk);
    std::copy(other._sk.begin(), other._sk.end(), replacement_sk.begin());

    std::vector<uint8_t> replacement_key(other._key.size(), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> key_guard(replacement_key);
    std::copy(other._key.begin(), other._key.end(), replacement_key.begin());
    std::vector<uint8_t> replacement_ct(other._ct);

    _pk.swap(replacement_pk);
    wipe_vector_storage(_sk);
    _sk.swap(replacement_sk);
    wipe_vector_storage(_key);
    _key.swap(replacement_key);
    _ct.swap(replacement_ct);
    return *this;
}

Kyber::~Kyber()
{
    wipe_vector_storage(_sk);
    wipe_vector_storage(_key);
}

bool Kyber::kem_encode(const std::vector<uint8_t> &other_pk)
{
    wipe_and_clear(_key);
    wipe_and_clear(_ct);

    if (other_pk.size() != KYBER_PUBLICKEYBYTES) {
        return false;
    }

    std::vector<uint8_t> key(KYBER_SYMBYTES, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> key_guard(key);
    std::vector<uint8_t> ct(KYBER_CIPHERTEXTBYTES, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> ct_guard(ct);

    const auto validation_error = crypto_kem_enc(ct.data(),
                                                  key.data(),
                                                  other_pk.data());
    if (validation_error != 0) {
        return false;
    }

    _key.swap(key);
    _ct.swap(ct);
    return true;
}

bool Kyber::kem_decode(const std::vector<uint8_t> &cyphertext)
{
    wipe_and_clear(_key);

    if (cyphertext.size() != KYBER_CIPHERTEXTBYTES ||
        _sk.size() != KYBER_SECRETKEYBYTES) {
        return false;
    }

    std::vector<uint8_t> key(KYBER_SYMBYTES, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> key_guard(key);

    const auto validation_error = crypto_kem_dec(key.data(),
                                                  cyphertext.data(),
                                                  _sk.data());

    // The reference backend returns -1 for a well-sized invalid ciphertext and
    // deliberately writes an implicit-rejection key. Preserve that contract.
    if (validation_error != 0 && validation_error != -1) {
        return false;
    }

    _key.swap(key);
    return validation_error == 0;
}
