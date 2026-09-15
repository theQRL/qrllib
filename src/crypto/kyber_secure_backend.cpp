// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

// Parent-owned secret-bearing entry points for the historical Kyber backend.
// The arithmetic and serialization match the vendored reference source; the
// only lifecycle change is deterministic erasure of addressable scratch.

#include "secure_memory.h"
#include "system_random.h"

#include <kyber/ref/api.h>
#include <kyber/ref/cbd.h>
#include <kyber/ref/fips202.h>
#include <kyber/ref/indcpa.h>
#include <kyber/ref/kex.h>
#include <kyber/ref/params.h>
#include <kyber/ref/poly.h>
#include <kyber/ref/polyvec.h>
#include <kyber/ref/reduce.h>
#include <kyber/ref/verify.h>

#include <cstddef>
#include <cstdint>

void gen_matrix(polyvec* matrix, const unsigned char* seed, int transposed);

namespace {

struct KemEncodeScratch {
    unsigned char kr[2 * KYBER_SYMBYTES]{};
    unsigned char buf[2 * KYBER_SYMBYTES]{};
};

struct KemDecodeScratch {
    unsigned char comparison[KYBER_CIPHERTEXTBYTES]{};
    unsigned char buf[2 * KYBER_SYMBYTES]{};
    unsigned char kr[2 * KYBER_SYMBYTES]{};
};

struct IndcpaKeypairScratch {
    polyvec matrix[KYBER_K]{};
    polyvec error{};
    polyvec public_key{};
    polyvec secret_key{};
    unsigned char seed[2 * KYBER_SYMBYTES]{};
};

struct IndcpaEncodeScratch {
    polyvec secret{};
    polyvec public_key{};
    polyvec error{};
    polyvec matrix[KYBER_K]{};
    polyvec ciphertext{};
    poly value{};
    poly message{};
    poly scalar_error{};
    unsigned char seed[KYBER_SYMBYTES]{};
};

struct IndcpaDecodeScratch {
    polyvec ciphertext{};
    polyvec secret_key{};
    poly value{};
    poly message{};
};

struct NoiseScratch {
    unsigned char bytes[KYBER_ETA * KYBER_N / 4]{};
    unsigned char extended_seed[KYBER_SYMBYTES + 1]{};
};

struct MessageScratch {
    volatile std::uint16_t mask{};
};

void pack_public_key(unsigned char* output,
                     const polyvec* public_key,
                     const unsigned char* seed)
{
    polyvec_compress(output, public_key);
    for (int i = 0; i < KYBER_SYMBYTES; ++i) {
        output[i + KYBER_POLYVECCOMPRESSEDBYTES] = seed[i];
    }
}

void unpack_public_key(polyvec* public_key,
                       unsigned char* seed,
                       const unsigned char* packed)
{
    polyvec_decompress(public_key, packed);
    for (int i = 0; i < KYBER_SYMBYTES; ++i) {
        seed[i] = packed[i + KYBER_POLYVECCOMPRESSEDBYTES];
    }
}

void pack_ciphertext(unsigned char* output,
                     const polyvec* vector,
                     const poly* value)
{
    polyvec_compress(output, vector);
    poly_compress(output + KYBER_POLYVECCOMPRESSEDBYTES, value);
}

void unpack_ciphertext(polyvec* vector,
                       poly* value,
                       const unsigned char* input)
{
    polyvec_decompress(vector, input);
    poly_decompress(value, input + KYBER_POLYVECCOMPRESSEDBYTES);
}

void pack_secret_key(unsigned char* output, const polyvec* secret_key)
{
    polyvec_tobytes(output, secret_key);
}

void unpack_secret_key(polyvec* secret_key, const unsigned char* input)
{
    polyvec_frombytes(secret_key, input);
}

std::uint64_t load_little_endian(const unsigned char* input, int bytes)
{
    std::uint64_t result = input[0];
    for (int i = 1; i < bytes; ++i) {
        result |= static_cast<std::uint64_t>(input[i]) << (8 * i);
    }
    return result;
}

}  // namespace

void indcpa_keypair(unsigned char* pk, unsigned char* sk)
{
    IndcpaKeypairScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    unsigned char* const public_seed = scratch.seed;
    unsigned char* const noise_seed = scratch.seed + KYBER_SYMBYTES;
    unsigned char nonce = 0;

    randombytes(scratch.seed, KYBER_SYMBYTES);
    sha3_512(scratch.seed, scratch.seed, KYBER_SYMBYTES);
    gen_matrix(scratch.matrix, public_seed, 0);

    for (int i = 0; i < KYBER_K; ++i) {
        poly_getnoise(scratch.secret_key.vec + i, noise_seed, nonce++);
    }
    polyvec_ntt(&scratch.secret_key);
    for (int i = 0; i < KYBER_K; ++i) {
        poly_getnoise(scratch.error.vec + i, noise_seed, nonce++);
    }
    for (int i = 0; i < KYBER_K; ++i) {
        polyvec_pointwise_acc(scratch.public_key.vec + i,
                              &scratch.secret_key,
                              scratch.matrix + i);
    }
    polyvec_invntt(&scratch.public_key);
    polyvec_add(&scratch.public_key,
                &scratch.public_key,
                &scratch.error);

    pack_secret_key(sk, &scratch.secret_key);
    pack_public_key(pk, &scratch.public_key, public_seed);
}

void indcpa_enc(unsigned char* ciphertext,
                const unsigned char* message,
                const unsigned char* public_key,
                const unsigned char* coins)
{
    IndcpaEncodeScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    unsigned char nonce = 0;

    unpack_public_key(&scratch.public_key, scratch.seed, public_key);
    poly_frommsg(&scratch.message, message);
    polyvec_ntt(&scratch.public_key);
    gen_matrix(scratch.matrix, scratch.seed, 1);

    for (int i = 0; i < KYBER_K; ++i) {
        poly_getnoise(scratch.secret.vec + i, coins, nonce++);
    }
    polyvec_ntt(&scratch.secret);
    for (int i = 0; i < KYBER_K; ++i) {
        poly_getnoise(scratch.error.vec + i, coins, nonce++);
    }
    for (int i = 0; i < KYBER_K; ++i) {
        polyvec_pointwise_acc(scratch.ciphertext.vec + i,
                              &scratch.secret,
                              scratch.matrix + i);
    }
    polyvec_invntt(&scratch.ciphertext);
    polyvec_add(&scratch.ciphertext,
                &scratch.ciphertext,
                &scratch.error);

    polyvec_pointwise_acc(&scratch.value,
                          &scratch.public_key,
                          &scratch.secret);
    poly_invntt(&scratch.value);
    poly_getnoise(&scratch.scalar_error, coins, nonce++);
    poly_add(&scratch.value, &scratch.value, &scratch.scalar_error);
    poly_add(&scratch.value, &scratch.value, &scratch.message);
    pack_ciphertext(ciphertext, &scratch.ciphertext, &scratch.value);
}

void indcpa_dec(unsigned char* message,
                const unsigned char* ciphertext,
                const unsigned char* secret_key)
{
    IndcpaDecodeScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    unpack_ciphertext(&scratch.ciphertext, &scratch.value, ciphertext);
    unpack_secret_key(&scratch.secret_key, secret_key);
    polyvec_ntt(&scratch.ciphertext);
    polyvec_pointwise_acc(&scratch.message,
                          &scratch.secret_key,
                          &scratch.ciphertext);
    poly_invntt(&scratch.message);
    poly_sub(&scratch.message, &scratch.message, &scratch.value);
    poly_tomsg(message, &scratch.message);
}

int qrllib_kyber_crypto_kem_keypair_unchecked(unsigned char* pk,
                                              unsigned char* sk)
{
    indcpa_keypair(pk, sk);
    for (std::size_t i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; ++i) {
        sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
    }
    sha3_256(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
             pk,
             KYBER_PUBLICKEYBYTES);
    randombytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
                KYBER_SYMBYTES);
    return 0;
}

int qrllib_kyber_crypto_kem_enc_unchecked(unsigned char* ciphertext,
                                          unsigned char* shared_secret,
                                          const unsigned char* public_key)
{
    KemEncodeScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    randombytes(scratch.buf, KYBER_SYMBYTES);
    sha3_256(scratch.buf, scratch.buf, KYBER_SYMBYTES);
    sha3_256(scratch.buf + KYBER_SYMBYTES,
             public_key,
             KYBER_PUBLICKEYBYTES);
    sha3_512(scratch.kr, scratch.buf, 2 * KYBER_SYMBYTES);
    indcpa_enc(ciphertext,
               scratch.buf,
               public_key,
               scratch.kr + KYBER_SYMBYTES);
    sha3_256(scratch.kr + KYBER_SYMBYTES,
             ciphertext,
             KYBER_CIPHERTEXTBYTES);
    sha3_256(shared_secret, scratch.kr, 2 * KYBER_SYMBYTES);
    return 0;
}

int crypto_kem_dec(unsigned char* shared_secret,
                   const unsigned char* ciphertext,
                   const unsigned char* secret_key)
{
    KemDecodeScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    const unsigned char* const public_key =
        secret_key + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(scratch.buf, ciphertext, secret_key);
    for (std::size_t i = 0; i < KYBER_SYMBYTES; ++i) {
        scratch.buf[KYBER_SYMBYTES + i] =
            secret_key[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];
    }
    sha3_512(scratch.kr, scratch.buf, 2 * KYBER_SYMBYTES);
    indcpa_enc(scratch.comparison,
               scratch.buf,
               public_key,
               scratch.kr + KYBER_SYMBYTES);
    const int failed = verify(ciphertext,
                              scratch.comparison,
                              KYBER_CIPHERTEXTBYTES);
    sha3_256(scratch.kr + KYBER_SYMBYTES,
             ciphertext,
             KYBER_CIPHERTEXTBYTES);
    cmov(scratch.kr,
         secret_key + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
         KYBER_SYMBYTES,
         static_cast<unsigned char>(failed));
    sha3_256(shared_secret, scratch.kr, 2 * KYBER_SYMBYTES);
    return -failed;
}

void poly_getnoise(poly* output,
                   const unsigned char* seed,
                   unsigned char nonce)
{
    NoiseScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    for (int i = 0; i < KYBER_SYMBYTES; ++i) {
        scratch.extended_seed[i] = seed[i];
    }
    scratch.extended_seed[KYBER_SYMBYTES] = nonce;
    shake256(scratch.bytes,
             KYBER_ETA * KYBER_N / 4,
             scratch.extended_seed,
             KYBER_SYMBYTES + 1);
    cbd(output, scratch.bytes);
}

void poly_frommsg(poly* output,
                  const unsigned char message[KYBER_SYMBYTES])
{
    MessageScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));

    for (int i = 0; i < KYBER_SYMBYTES; ++i) {
        for (int j = 0; j < 8; ++j) {
            scratch.mask = static_cast<std::uint16_t>(
                -static_cast<int>((message[i] >> j) & 1));
            output->coeffs[8 * i + j] = static_cast<std::uint16_t>(
                scratch.mask & ((KYBER_Q + 1) / 2));
        }
    }
}

void poly_tobytes(unsigned char* output, const poly* input)
{
    std::uint16_t temporary[8]{};
    qrllib::secure_memory::RangeWipeGuard wipe(temporary,
                                                sizeof(temporary));
    for (int i = 0; i < KYBER_N / 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            temporary[j] = freeze(input->coeffs[8 * i + j]);
        }
        output[13 * i + 0] = temporary[0] & 0xff;
        output[13 * i + 1] = static_cast<unsigned char>(
            (temporary[0] >> 8) | ((temporary[1] & 0x07) << 5));
        output[13 * i + 2] = (temporary[1] >> 3) & 0xff;
        output[13 * i + 3] = static_cast<unsigned char>(
            (temporary[1] >> 11) | ((temporary[2] & 0x3f) << 2));
        output[13 * i + 4] = static_cast<unsigned char>(
            (temporary[2] >> 6) | ((temporary[3] & 0x01) << 7));
        output[13 * i + 5] = (temporary[3] >> 1) & 0xff;
        output[13 * i + 6] = static_cast<unsigned char>(
            (temporary[3] >> 9) | ((temporary[4] & 0x0f) << 4));
        output[13 * i + 7] = (temporary[4] >> 4) & 0xff;
        output[13 * i + 8] = static_cast<unsigned char>(
            (temporary[4] >> 12) | ((temporary[5] & 0x7f) << 1));
        output[13 * i + 9] = static_cast<unsigned char>(
            (temporary[5] >> 7) | ((temporary[6] & 0x03) << 6));
        output[13 * i + 10] = (temporary[6] >> 2) & 0xff;
        output[13 * i + 11] = static_cast<unsigned char>(
            (temporary[6] >> 10) | ((temporary[7] & 0x1f) << 3));
        output[13 * i + 12] =
            static_cast<unsigned char>(temporary[7] >> 5);
    }
}

void cbd(poly* output, const unsigned char* input)
{
#if KYBER_ETA == 3
    struct CbdScratch {
        std::uint32_t value{};
        std::uint32_t sums{};
        std::uint32_t positive[4]{};
        std::uint32_t negative[4]{};
    } scratch{};
#elif KYBER_ETA == 4
    struct CbdScratch {
        std::uint32_t value{};
        std::uint32_t sums{};
        std::uint32_t positive[4]{};
        std::uint32_t negative[4]{};
    } scratch{};
#elif KYBER_ETA == 5
    struct CbdScratch {
        std::uint64_t value{};
        std::uint64_t sums{};
        std::uint64_t positive[4]{};
        std::uint64_t negative[4]{};
    } scratch{};
#else
#error "cbd only supports KYBER_ETA in {3,4,5}"
#endif
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));

    for (int i = 0; i < KYBER_N / 4; ++i) {
#if KYBER_ETA == 3
        scratch.value = load_little_endian(input + 3 * i, 3);
        scratch.sums = 0;
        for (int j = 0; j < 3; ++j) {
            scratch.sums += (scratch.value >> j) & 0x249249;
        }
        scratch.positive[0] = scratch.sums & 0x7;
        scratch.negative[0] = (scratch.sums >> 3) & 0x7;
        scratch.positive[1] = (scratch.sums >> 6) & 0x7;
        scratch.negative[1] = (scratch.sums >> 9) & 0x7;
        scratch.positive[2] = (scratch.sums >> 12) & 0x7;
        scratch.negative[2] = (scratch.sums >> 15) & 0x7;
        scratch.positive[3] = (scratch.sums >> 18) & 0x7;
        scratch.negative[3] = scratch.sums >> 21;
#elif KYBER_ETA == 4
        scratch.value = static_cast<std::uint32_t>(
            load_little_endian(input + 4 * i, 4));
        scratch.sums = 0;
        for (int j = 0; j < 4; ++j) {
            scratch.sums += (scratch.value >> j) & 0x11111111;
        }
        scratch.positive[0] = scratch.sums & 0xf;
        scratch.negative[0] = (scratch.sums >> 4) & 0xf;
        scratch.positive[1] = (scratch.sums >> 8) & 0xf;
        scratch.negative[1] = (scratch.sums >> 12) & 0xf;
        scratch.positive[2] = (scratch.sums >> 16) & 0xf;
        scratch.negative[2] = (scratch.sums >> 20) & 0xf;
        scratch.positive[3] = (scratch.sums >> 24) & 0xf;
        scratch.negative[3] = scratch.sums >> 28;
#elif KYBER_ETA == 5
        scratch.value = load_little_endian(input + 5 * i, 5);
        scratch.sums = 0;
        for (int j = 0; j < 5; ++j) {
            scratch.sums += (scratch.value >> j) & 0x0842108421ULL;
        }
        scratch.positive[0] = scratch.sums & 0x1f;
        scratch.negative[0] = (scratch.sums >> 5) & 0x1f;
        scratch.positive[1] = (scratch.sums >> 10) & 0x1f;
        scratch.negative[1] = (scratch.sums >> 15) & 0x1f;
        scratch.positive[2] = (scratch.sums >> 20) & 0x1f;
        scratch.negative[2] = (scratch.sums >> 25) & 0x1f;
        scratch.positive[3] = (scratch.sums >> 30) & 0x1f;
        scratch.negative[3] = scratch.sums >> 35;
#endif
        for (int j = 0; j < 4; ++j) {
            output->coeffs[4 * i + j] = static_cast<std::uint16_t>(
                scratch.positive[j] + KYBER_Q - scratch.negative[j]);
        }
    }
}

void qrllib_kyber_uake_initA_unchecked(u8* send,
                                      u8* temporary_key,
                                      u8* secret_key,
                                      const u8* peer_public_key)
{
    crypto_kem_keypair(send, secret_key);
    crypto_kem_enc(send + KYBER_PUBLICKEYBYTES,
                   temporary_key,
                   peer_public_key);
}

void qrllib_kyber_uake_sharedB_unchecked(u8* send,
                                        u8* shared_key,
                                        const u8* received,
                                        const u8* secret_key)
{
    unsigned char scratch[2 * KYBER_SYMBYTES]{};
    qrllib::secure_memory::RangeWipeGuard wipe(scratch, sizeof(scratch));
    crypto_kem_enc(send, scratch, received);
    crypto_kem_dec(scratch + KYBER_SYMBYTES,
                   received + KYBER_PUBLICKEYBYTES,
                   secret_key);
    shake256(shared_key, KYBER_SYMBYTES, scratch, sizeof(scratch));
}

void kyber_uake_sharedA(u8* shared_key,
                        const u8* received,
                        const u8* temporary_key,
                        const u8* secret_key)
{
    unsigned char scratch[2 * KYBER_SYMBYTES]{};
    qrllib::secure_memory::RangeWipeGuard wipe(scratch, sizeof(scratch));
    crypto_kem_dec(scratch, received, secret_key);
    for (int i = 0; i < KYBER_SYMBYTES; ++i) {
        scratch[i + KYBER_SYMBYTES] = temporary_key[i];
    }
    shake256(shared_key, KYBER_SYMBYTES, scratch, sizeof(scratch));
}

void qrllib_kyber_ake_initA_unchecked(u8* send,
                                     u8* temporary_key,
                                     u8* secret_key,
                                     const u8* peer_public_key)
{
    crypto_kem_keypair(send, secret_key);
    crypto_kem_enc(send + KYBER_PUBLICKEYBYTES,
                   temporary_key,
                   peer_public_key);
}

void qrllib_kyber_ake_sharedB_unchecked(u8* send,
                                       u8* shared_key,
                                       const u8* received,
                                       const u8* secret_key,
                                       const u8* public_key)
{
    unsigned char scratch[3 * KYBER_SYMBYTES]{};
    qrllib::secure_memory::RangeWipeGuard wipe(scratch, sizeof(scratch));
    crypto_kem_enc(send, scratch, received);
    crypto_kem_enc(send + KYBER_CIPHERTEXTBYTES,
                   scratch + KYBER_SYMBYTES,
                   public_key);
    crypto_kem_dec(scratch + 2 * KYBER_SYMBYTES,
                   received + KYBER_PUBLICKEYBYTES,
                   secret_key);
    shake256(shared_key, KYBER_SYMBYTES, scratch, sizeof(scratch));
}

void kyber_ake_sharedA(u8* shared_key,
                       const u8* received,
                       const u8* temporary_key,
                       const u8* secret_key,
                       const u8* static_secret_key)
{
    unsigned char scratch[3 * KYBER_SYMBYTES]{};
    qrllib::secure_memory::RangeWipeGuard wipe(scratch, sizeof(scratch));
    crypto_kem_dec(scratch, received, secret_key);
    crypto_kem_dec(scratch + KYBER_SYMBYTES,
                   received + KYBER_CIPHERTEXTBYTES,
                   static_secret_key);
    for (int i = 0; i < KYBER_SYMBYTES; ++i) {
        scratch[i + 2 * KYBER_SYMBYTES] = temporary_key[i];
    }
    shake256(shared_key, KYBER_SYMBYTES, scratch, sizeof(scratch));
}
