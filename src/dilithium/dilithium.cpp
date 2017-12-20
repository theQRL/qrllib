// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include "dilithium.h"

Dilithium::Dilithium()
{
    // TODO: Initialize keys randomly (seed?)
    _pk.resize(CRYPTO_PUBLICKEYBYTES);
    _sk.resize(CRYPTO_SECRETKEYBYTES);
    crypto_sign_keypair(_pk.data(), _sk.data());
}

Dilithium::Dilithium(const std::vector<uint8_t> &pk, const std::vector<uint8_t> &sk):
    _pk(pk),
    _sk(sk)
{
    // TODO: Verify sizes - CRYPTO_SECRETKEYBYTES / CRYPTO_PUBLICKEYBYTES
}

std::vector<uint8_t> Dilithium::sign(const std::vector<uint8_t> &message)
{
    unsigned long long message_signed_size_dummy;

    std::vector<unsigned char> message_signed(message.size() + CRYPTO_BYTES);

    crypto_sign(message_signed.data(),
                &message_signed_size_dummy,
                message.data(),
                message.size(),
                _sk.data());

    return message_signed;

// TODO: Leon, return only signature?
//    return std::vector<unsigned char>(message_signed.begin()+message.size(),
//                                      message_signed.end());
}

bool Dilithium::sign_open(std::vector<uint8_t> &message_output,
                          const std::vector<uint8_t> &message_signed,
                          const std::vector<uint8_t> &pk)
{
    auto message_size = message_signed.size();
    message_output.resize(message_size);

    unsigned long long message_output_dummy;
    auto ret = crypto_sign_open(message_output.data(),
                     &message_output_dummy,
                     message_signed.data(),
                     message_signed.size(),
                     pk.data());

    // TODO Leon: message_out has size()+CRYPTO_BYTES. Should we return just the message?
    return ret == 0;
}

std::vector<uint8_t> Dilithium::extract_message(std::vector<uint8_t> &message_output)
{
    return std::vector<uint8_t>(message_output.begin(), message_output.end() - CRYPTO_BYTES);
}

std::vector<uint8_t> Dilithium::extract_signature(std::vector<uint8_t> &message_output)
{
    return std::vector<uint8_t>(message_output.end() - CRYPTO_BYTES, message_output.end());
}
