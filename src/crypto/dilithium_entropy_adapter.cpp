// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "secure_memory.h"
#include "system_random.h"

#include <dilithium/ref/api.h>

int qrllib_dilithium_crypto_sign_keypair_unchecked(unsigned char* public_key,
                                                   unsigned char* secret_key);

int crypto_sign_keypair(unsigned char* public_key, unsigned char* secret_key)
{
    qrllib_entropy_operation_begin();
    const int backend_status =
        qrllib_dilithium_crypto_sign_keypair_unchecked(public_key, secret_key);
    const int entropy_status = qrllib_entropy_operation_end();

    if (backend_status != 0 || entropy_status != 0) {
        qrllib::secure_memory::secure_zero(public_key, CRYPTO_PUBLICKEYBYTES);
        qrllib::secure_memory::secure_zero(secret_key, CRYPTO_SECRETKEYBYTES);
        return -1;
    }
    return 0;
}
