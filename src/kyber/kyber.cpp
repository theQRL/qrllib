// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <stdexcept>
#include "kyber.h"

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

    _pk = pk;
    _sk = sk;
}

Kyber::Kyber()
{
    _pk.resize(KYBER_PUBLICKEYBYTES, 0);
    _sk.resize(KYBER_SECRETKEYBYTES, 0);

    crypto_kem_keypair(_pk.data(), _sk.data());
}

bool Kyber::kem_encode(const std::vector<uint8_t> &other_pk)
{
    // TODO: Verify sizes (other_pk)

    _key.resize(KYBER_SYMBYTES);
    _ct.resize(KYBER_CIPHERTEXTBYTES);

    auto validation_error = crypto_kem_enc(_ct.data(),
                                           _key.data(),
                                           other_pk.data());

    return validation_error == 0;
}

bool Kyber::kem_decode(const std::vector<uint8_t> &cyphertext)
{
    // TODO: Verify sizes (other_pk)
    _key.resize(KYBER_SYMBYTES);

    auto validation_error = crypto_kem_dec(_key.data(),
                                           cyphertext.data(),
                                           _sk.data());

    return validation_error == 0;
}
