// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#define DILITHIUM_PUBLICKEYBYTES 1472U
#define DILITHIUM_SECRETKEYBYTES 3504U
#define DILITHIUM_BYTES 2701U

extern "C" {
    int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

    int crypto_sign(unsigned char *sm,
                    unsigned long long *smlen,
                    const unsigned char *msg,
                    unsigned long long len,
                    const unsigned char *sk);

    int crypto_sign_open(unsigned char *m,
                         unsigned long long *mlen,
                         const unsigned char *sm,
                         unsigned long long smlen,
                         const unsigned char *pk);

    void randombytes(unsigned char *x, size_t xlen);
}
