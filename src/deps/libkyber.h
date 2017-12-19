// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#define DILITHIUM_PUBLICKEYBYTES 1472U
#define DILITHIUM_SECRETKEYBYTES 3504U
#define DILITHIUM_BYTES 2701U

extern "C" {

#include "kyber/ref/params.h"

int crypto_kem_keypair(unsigned char *pk,
                       unsigned char *sk);

int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

//void randombytes(unsigned char *x, size_t xlen);
}
