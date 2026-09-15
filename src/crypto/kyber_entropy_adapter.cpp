// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "secure_memory.h"
#include "system_random.h"

#include <kyber/ref/api.h>
#include <kyber/ref/kex.h>

int qrllib_kyber_crypto_kem_keypair_unchecked(unsigned char* public_key,
                                              unsigned char* secret_key);
int qrllib_kyber_crypto_kem_enc_unchecked(unsigned char* ciphertext,
                                          unsigned char* shared_secret,
                                          const unsigned char* public_key);

void qrllib_kyber_uake_initA_unchecked(u8* send,
                                      u8* temporary_key,
                                      u8* secret_key,
                                      const u8* peer_public_key);
void qrllib_kyber_uake_sharedB_unchecked(u8* send,
                                        u8* shared_key,
                                        const u8* received,
                                        const u8* secret_key);
void qrllib_kyber_ake_initA_unchecked(u8* send,
                                     u8* temporary_key,
                                     u8* secret_key,
                                     const u8* peer_public_key);
void qrllib_kyber_ake_sharedB_unchecked(u8* send,
                                       u8* shared_key,
                                       const u8* received,
                                       const u8* secret_key,
                                       const u8* public_key);

namespace {

void clear_keypair(unsigned char* public_key, unsigned char* secret_key)
{
    qrllib::secure_memory::secure_zero(public_key, CRYPTO_PUBLICKEYBYTES);
    qrllib::secure_memory::secure_zero(secret_key, CRYPTO_SECRETKEYBYTES);
}

}  // namespace

int crypto_kem_keypair(unsigned char* public_key, unsigned char* secret_key)
{
    qrllib_entropy_operation_begin();
    const int backend_status =
        qrllib_kyber_crypto_kem_keypair_unchecked(public_key, secret_key);
    const int entropy_status = qrllib_entropy_operation_end();

    if (backend_status != 0 || entropy_status != 0) {
        clear_keypair(public_key, secret_key);
        return -1;
    }
    return 0;
}

int crypto_kem_enc(unsigned char* ciphertext,
                   unsigned char* shared_secret,
                   const unsigned char* public_key)
{
    qrllib_entropy_operation_begin();
    const int backend_status = qrllib_kyber_crypto_kem_enc_unchecked(
        ciphertext, shared_secret, public_key);
    const int entropy_status = qrllib_entropy_operation_end();

    if (backend_status != 0 || entropy_status != 0) {
        qrllib::secure_memory::secure_zero(ciphertext,
                                           CRYPTO_CIPHERTEXTBYTES);
        qrllib::secure_memory::secure_zero(shared_secret, CRYPTO_BYTES);
        return -1;
    }
    return 0;
}

void kyber_uake_initA(u8* send,
                      u8* temporary_key,
                      u8* secret_key,
                      const u8* peer_public_key)
{
    qrllib_entropy_operation_begin();
    qrllib_kyber_uake_initA_unchecked(send,
                                     temporary_key,
                                     secret_key,
                                     peer_public_key);
    if (qrllib_entropy_operation_end() != 0) {
        qrllib::secure_memory::secure_zero(send, KYBER_UAKE_SENDABYTES);
        qrllib::secure_memory::secure_zero(temporary_key, KYBER_SYMBYTES);
        qrllib::secure_memory::secure_zero(secret_key,
                                           CRYPTO_SECRETKEYBYTES);
    }
}

void kyber_uake_sharedB(u8* send,
                        u8* shared_key,
                        const u8* received,
                        const u8* secret_key)
{
    qrllib_entropy_operation_begin();
    qrllib_kyber_uake_sharedB_unchecked(send,
                                       shared_key,
                                       received,
                                       secret_key);
    if (qrllib_entropy_operation_end() != 0) {
        qrllib::secure_memory::secure_zero(send, KYBER_UAKE_SENDBBYTES);
        qrllib::secure_memory::secure_zero(shared_key, KYBER_SYMBYTES);
    }
}

void kyber_ake_initA(u8* send,
                     u8* temporary_key,
                     u8* secret_key,
                     const u8* peer_public_key)
{
    qrllib_entropy_operation_begin();
    qrllib_kyber_ake_initA_unchecked(send,
                                    temporary_key,
                                    secret_key,
                                    peer_public_key);
    if (qrllib_entropy_operation_end() != 0) {
        qrllib::secure_memory::secure_zero(send, KYBER_AKE_SENDABYTES);
        qrllib::secure_memory::secure_zero(temporary_key, KYBER_SYMBYTES);
        qrllib::secure_memory::secure_zero(secret_key,
                                           CRYPTO_SECRETKEYBYTES);
    }
}

void kyber_ake_sharedB(u8* send,
                       u8* shared_key,
                       const u8* received,
                       const u8* secret_key,
                       const u8* public_key)
{
    qrllib_entropy_operation_begin();
    qrllib_kyber_ake_sharedB_unchecked(send,
                                      shared_key,
                                      received,
                                      secret_key,
                                      public_key);
    if (qrllib_entropy_operation_end() != 0) {
        qrllib::secure_memory::secure_zero(send, KYBER_AKE_SENDBBYTES);
        qrllib::secure_memory::secure_zero(shared_key, KYBER_SYMBYTES);
    }
}
