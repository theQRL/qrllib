// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

// The historical Dilithium reference implementation keeps expanded secret
// material in ordinary automatic arrays.  Keep the algorithm and wire format
// unchanged, but own the secret-bearing entry points so every directly
// addressable scratch object is erased on all C++ exits.

#include "secure_memory.h"
#include "system_random.h"

#include <dilithium/ref/api.h>
#include <dilithium/ref/fips202.h>
#include <dilithium/ref/packing.h>
#include <dilithium/ref/params.h>
#include <dilithium/ref/poly.h>
#include <dilithium/ref/polyvec.h>
#include <dilithium/ref/reduce.h>
#include <dilithium/ref/sign.h>

#include <cstdint>

namespace {

struct KeypairScratch {
    unsigned char seedbuf[3 * SEEDBYTES]{};
    unsigned char tr[CRHBYTES]{};
    polyvecl mat[K]{};
    polyvecl s1{};
    polyvecl s1hat{};
    polyveck s2{};
    polyveck t{};
    polyveck t1{};
    polyveck t0{};
};

struct SignScratch {
    unsigned char seedbuf[2 * SEEDBYTES + CRHBYTES]{};
    poly c{};
    poly chat{};
    polyvecl mat[K]{};
    polyvecl s1{};
    polyvecl y{};
    polyvecl yhat{};
    polyvecl z{};
    polyveck s2{};
    polyveck t0{};
    polyveck w{};
    polyveck w1{};
    polyveck h{};
    polyveck wcs2{};
    polyveck wcs20{};
    polyveck ct0{};
    polyveck tmp{};
};

struct EtaScratch {
    unsigned char inbuf[SEEDBYTES + 1]{};
    unsigned char outbuf[2 * SHAKE256_RATE]{};
    std::uint64_t state[25]{};
};

struct GammaScratch {
    unsigned char inbuf[SEEDBYTES + CRHBYTES + 2]{};
    unsigned char outbuf[5 * SHAKE256_RATE]{};
    std::uint64_t state[25]{};
};

struct ChallengeScratch {
    unsigned char inbuf[CRHBYTES + K * POLW1_SIZE_PACKED]{};
    unsigned char outbuf[SHAKE256_RATE]{};
    std::uint64_t state[25]{};
    std::uint64_t signs{};
    std::uint64_t mask{};
    unsigned int byte{};
    unsigned int position{};
};

struct MatrixScratch {
    unsigned char inbuf[SEEDBYTES + 1]{};
    unsigned char outbuf[5 * SHAKE128_RATE]{};
    std::uint32_t value{};
    unsigned int position{};
    unsigned int count{};
};

struct VerifyScratch {
    unsigned char rho[SEEDBYTES]{};
    unsigned char mu[CRHBYTES]{};
    poly challenge{};
    poly challenge_ntt{};
    poly expected_challenge{};
    polyvecl matrix[K]{};
    polyvecl response{};
    polyveck public_key{};
    polyveck high_bits{};
    polyveck hints{};
    polyveck product{};
    polyveck challenge_product{};
};

unsigned int reject_eta(std::uint32_t* output,
                        unsigned int length,
                        const unsigned char* input,
                        unsigned int input_length)
{
#if ETA > 7
#error "reject_eta assumes ETA <= 7"
#endif
    unsigned int count = 0;
    unsigned int position = 0;
    while (count < length) {
#if ETA <= 3
        const unsigned char t0 = input[position] & 0x07;
        const unsigned char t1 = input[position++] >> 5;
#else
        const unsigned char t0 = input[position] & 0x0f;
        const unsigned char t1 = input[position++] >> 4;
#endif
        if (t0 <= 2 * ETA) {
            output[count++] = Q + ETA - t0;
        }
        if (t1 <= 2 * ETA && count < length) {
            output[count++] = Q + ETA - t1;
        }
        if (position >= input_length) {
            break;
        }
    }
    return count;
}

unsigned int reject_gamma1m1(std::uint32_t* output,
                             unsigned int length,
                             const unsigned char* input,
                             unsigned int input_length)
{
#if GAMMA1 > (1 << 19)
#error "reject_gamma1m1 assumes GAMMA1 - 1 fits in 19 bits"
#endif
    unsigned int count = 0;
    unsigned int position = 0;
    while (count < length) {
        std::uint32_t t0 = input[position];
        t0 |= static_cast<std::uint32_t>(input[position + 1]) << 8;
        t0 |= static_cast<std::uint32_t>(input[position + 2]) << 16;
        t0 &= 0xfffff;

        std::uint32_t t1 = input[position + 2] >> 4;
        t1 |= static_cast<std::uint32_t>(input[position + 3]) << 4;
        t1 |= static_cast<std::uint32_t>(input[position + 4]) << 12;
        position += 5;

        if (t0 <= 2 * GAMMA1 - 2) {
            output[count++] = Q + GAMMA1 - 1 - t0;
        }
        if (t1 <= 2 * GAMMA1 - 2 && count < length) {
            output[count++] = Q + GAMMA1 - 1 - t1;
        }
        if (position > input_length - 5) {
            break;
        }
    }
    return count;
}

}  // namespace

void expand_mat(polyvecl matrix[K],
                const unsigned char rho[SEEDBYTES])
{
    MatrixScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));

    for (unsigned int i = 0; i < SEEDBYTES; ++i) {
        scratch.inbuf[i] = rho[i];
    }

    for (unsigned int i = 0; i < K; ++i) {
        for (unsigned int j = 0; j < L; ++j) {
            scratch.count = 0;
            scratch.position = 0;
            scratch.inbuf[SEEDBYTES] =
                static_cast<unsigned char>(i + (j << 4));
            shake128(scratch.outbuf,
                     sizeof(scratch.outbuf),
                     scratch.inbuf,
                     SEEDBYTES + 1);

            while (scratch.count < N) {
                scratch.value = scratch.outbuf[scratch.position++];
                scratch.value |= static_cast<std::uint32_t>(
                                     scratch.outbuf[scratch.position++])
                                 << 8;
                scratch.value |= static_cast<std::uint32_t>(
                                     scratch.outbuf[scratch.position++])
                                 << 16;
                scratch.value &= 0x7fffff;
                if (scratch.value < Q) {
                    matrix[i].vec[j].coeffs[scratch.count++] =
                        scratch.value;
                }
            }
        }
    }
}

void challenge(poly* output,
               const unsigned char mu[CRHBYTES],
               const polyveck* high_bits)
{
    ChallengeScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));

    for (unsigned int i = 0; i < CRHBYTES; ++i) {
        scratch.inbuf[i] = mu[i];
    }
    for (unsigned int i = 0; i < K; ++i) {
        polyw1_pack(scratch.inbuf + CRHBYTES
                        + i * POLW1_SIZE_PACKED,
                    high_bits->vec + i);
    }

    shake256_absorb(scratch.state, scratch.inbuf, sizeof(scratch.inbuf));
    shake256_squeezeblocks(scratch.outbuf, 1, scratch.state);

    for (unsigned int i = 0; i < 8; ++i) {
        scratch.signs |= static_cast<std::uint64_t>(scratch.outbuf[i])
                         << (8 * i);
    }
    scratch.position = 8;
    scratch.mask = 1;

    for (unsigned int i = 0; i < N; ++i) {
        output->coeffs[i] = 0;
    }
    for (unsigned int i = 196; i < 256; ++i) {
        do {
            if (scratch.position >= SHAKE256_RATE) {
                shake256_squeezeblocks(scratch.outbuf,
                                       1,
                                       scratch.state);
                scratch.position = 0;
            }
            scratch.byte = scratch.outbuf[scratch.position++];
        } while (scratch.byte > i);

        output->coeffs[i] = output->coeffs[scratch.byte];
        output->coeffs[scratch.byte] =
            (scratch.signs & scratch.mask) ? Q - 1 : 1;
        scratch.mask <<= 1;
    }
}

int qrllib_dilithium_crypto_sign_keypair_unchecked(unsigned char* pk,
                                                   unsigned char* sk)
{
    KeypairScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    unsigned char* const rho = scratch.seedbuf;
    unsigned char* const rhoprime = rho + SEEDBYTES;
    unsigned char* const key = rho + 2 * SEEDBYTES;
    std::uint16_t nonce = 0;

    randombytes(scratch.seedbuf, SEEDBYTES);
    shake256(scratch.seedbuf,
             3 * SEEDBYTES,
             scratch.seedbuf,
             SEEDBYTES);

    expand_mat(scratch.mat, rho);
    for (unsigned int i = 0; i < L; ++i) {
        poly_uniform_eta(&scratch.s1.vec[i],
                         rhoprime,
                         static_cast<unsigned char>(nonce++));
    }
    for (unsigned int i = 0; i < K; ++i) {
        poly_uniform_eta(&scratch.s2.vec[i],
                         rhoprime,
                         static_cast<unsigned char>(nonce++));
    }

    scratch.s1hat = scratch.s1;
    polyvecl_ntt(&scratch.s1hat);
    for (unsigned int i = 0; i < K; ++i) {
        polyvecl_pointwise_acc_invmontgomery(&scratch.t.vec[i],
                                             scratch.mat + i,
                                             &scratch.s1hat);
        poly_invntt_montgomery(scratch.t.vec + i);
    }

    polyveck_add(&scratch.t, &scratch.t, &scratch.s2);
    polyveck_freeze(&scratch.t);
    polyveck_power2round(&scratch.t1, &scratch.t0, &scratch.t);
    pack_pk(pk, rho, &scratch.t1);

    shake256(scratch.tr, CRHBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    pack_sk(sk,
            rho,
            key,
            scratch.tr,
            &scratch.s1,
            &scratch.s2,
            &scratch.t0);
    return 0;
}

int crypto_sign(unsigned char* sm,
                unsigned long long* smlen,
                const unsigned char* message,
                unsigned long long message_length,
                const unsigned char* sk)
{
    SignScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    unsigned char* const rho = scratch.seedbuf;
    unsigned char* const key = scratch.seedbuf + SEEDBYTES;
    unsigned char* const mu = scratch.seedbuf + 2 * SEEDBYTES;
    unsigned char* const tr = sm + CRYPTO_BYTES - CRHBYTES;
    std::uint16_t nonce = 0;

    unpack_sk(rho,
              key,
              tr,
              &scratch.s1,
              &scratch.s2,
              &scratch.t0,
              sk);

    for (unsigned long long i = 0; i < message_length; ++i) {
        sm[CRYPTO_BYTES + i] = message[i];
    }
    shake256(mu,
             CRHBYTES,
             sm + CRYPTO_BYTES - CRHBYTES,
             CRHBYTES + message_length);

    expand_mat(scratch.mat, rho);
    polyvecl_ntt(&scratch.s1);
    polyveck_ntt(&scratch.s2);
    polyveck_ntt(&scratch.t0);

reject:
    for (unsigned int i = 0; i < L; ++i) {
        poly_uniform_gamma1m1(scratch.y.vec + i, key, nonce++);
    }

    scratch.yhat = scratch.y;
    polyvecl_ntt(&scratch.yhat);
    for (unsigned int i = 0; i < K; ++i) {
        polyvecl_pointwise_acc_invmontgomery(scratch.w.vec + i,
                                             scratch.mat + i,
                                             &scratch.yhat);
        poly_invntt_montgomery(scratch.w.vec + i);
    }

    polyveck_freeze(&scratch.w);
    polyveck_decompose(&scratch.w1, &scratch.tmp, &scratch.w);
    challenge(&scratch.c, mu, &scratch.w1);

    scratch.chat = scratch.c;
    poly_ntt(&scratch.chat);
    for (unsigned int i = 0; i < L; ++i) {
        poly_pointwise_invmontgomery(scratch.z.vec + i,
                                     &scratch.chat,
                                     scratch.s1.vec + i);
        poly_invntt_montgomery(scratch.z.vec + i);
    }
    polyvecl_add(&scratch.z, &scratch.z, &scratch.y);
    polyvecl_freeze(&scratch.z);
    if (polyvecl_chknorm(&scratch.z, GAMMA1 - BETA)) {
        goto reject;
    }

    for (unsigned int i = 0; i < K; ++i) {
        poly_pointwise_invmontgomery(scratch.wcs2.vec + i,
                                     &scratch.chat,
                                     scratch.s2.vec + i);
        poly_invntt_montgomery(scratch.wcs2.vec + i);
    }
    polyveck_sub(&scratch.wcs2, &scratch.w, &scratch.wcs2);
    polyveck_freeze(&scratch.wcs2);
    polyveck_decompose(&scratch.tmp, &scratch.wcs20, &scratch.wcs2);
    polyveck_freeze(&scratch.wcs20);
    if (polyveck_chknorm(&scratch.wcs20, GAMMA2 - BETA)) {
        goto reject;
    }

    for (unsigned int i = 0; i < K; ++i) {
        for (unsigned int j = 0; j < N; ++j) {
            if (scratch.tmp.vec[i].coeffs[j] !=
                scratch.w1.vec[i].coeffs[j]) {
                goto reject;
            }
        }
    }

    for (unsigned int i = 0; i < K; ++i) {
        poly_pointwise_invmontgomery(scratch.ct0.vec + i,
                                     &scratch.chat,
                                     scratch.t0.vec + i);
        poly_invntt_montgomery(scratch.ct0.vec + i);
    }
    polyveck_freeze(&scratch.ct0);
    if (polyveck_chknorm(&scratch.ct0, GAMMA2)) {
        goto reject;
    }

    polyveck_add(&scratch.tmp, &scratch.wcs2, &scratch.ct0);
    polyveck_neg(&scratch.ct0);
    polyveck_freeze(&scratch.tmp);
    const unsigned int hints =
        polyveck_make_hint(&scratch.h, &scratch.tmp, &scratch.ct0);
    if (hints > OMEGA) {
        goto reject;
    }

    pack_sig(sm, &scratch.z, &scratch.h, &scratch.c);
    *smlen = message_length + CRYPTO_BYTES;
    return 0;
}

int crypto_sign_open(unsigned char* message,
                     unsigned long long* message_length,
                     const unsigned char* signed_message,
                     unsigned long long signed_message_length,
                     const unsigned char* public_key)
{
    VerifyScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));

    if (signed_message_length < CRYPTO_BYTES) {
        goto bad_signature;
    }

    *message_length = signed_message_length - CRYPTO_BYTES;
    unpack_pk(scratch.rho, &scratch.public_key, public_key);
    if (unpack_sig(&scratch.response,
                   &scratch.hints,
                   &scratch.challenge,
                   signed_message)) {
        goto bad_signature;
    }
    if (polyvecl_chknorm(&scratch.response, GAMMA1 - BETA)) {
        goto bad_signature;
    }

    for (unsigned long long i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i) {
        message[CRYPTO_BYTES - CRYPTO_PUBLICKEYBYTES + i] = public_key[i];
    }
    if (signed_message != message) {
        for (unsigned long long i = 0; i < *message_length; ++i) {
            message[CRYPTO_BYTES + i] =
                signed_message[CRYPTO_BYTES + i];
        }
    }

    shake256(message + CRYPTO_BYTES - CRHBYTES,
             CRHBYTES,
             message + CRYPTO_BYTES - CRYPTO_PUBLICKEYBYTES,
             CRYPTO_PUBLICKEYBYTES);
    shake256(scratch.mu,
             CRHBYTES,
             message + CRYPTO_BYTES - CRHBYTES,
             CRHBYTES + *message_length);

    expand_mat(scratch.matrix, scratch.rho);
    polyvecl_ntt(&scratch.response);
    for (unsigned int i = 0; i < K; ++i) {
        polyvecl_pointwise_acc_invmontgomery(
            scratch.product.vec + i,
            scratch.matrix + i,
            &scratch.response);
    }

    scratch.challenge_ntt = scratch.challenge;
    poly_ntt(&scratch.challenge_ntt);
    polyveck_shiftl(&scratch.public_key, D);
    polyveck_ntt(&scratch.public_key);
    for (unsigned int i = 0; i < K; ++i) {
        poly_pointwise_invmontgomery(
            scratch.challenge_product.vec + i,
            &scratch.challenge_ntt,
            scratch.public_key.vec + i);
    }

    polyveck_sub(&scratch.product,
                 &scratch.product,
                 &scratch.challenge_product);
    polyveck_freeze(&scratch.product);
    polyveck_invntt_montgomery(&scratch.product);
    polyveck_freeze(&scratch.product);
    polyveck_use_hint(&scratch.high_bits,
                      &scratch.product,
                      &scratch.hints);

    challenge(&scratch.expected_challenge,
              scratch.mu,
              &scratch.high_bits);
    for (unsigned int i = 0; i < N; ++i) {
        if (scratch.challenge.coeffs[i]
            != scratch.expected_challenge.coeffs[i]) {
            goto bad_signature;
        }
    }

    for (unsigned long long i = 0; i < *message_length; ++i) {
        message[i] = signed_message[CRYPTO_BYTES + i];
    }
    return 0;

bad_signature:
    *message_length = static_cast<unsigned long long>(-1);
    for (unsigned long long i = 0; i < signed_message_length; ++i) {
        message[i] = 0;
    }
    return -1;
}

void poly_uniform_eta(poly* output,
                      const unsigned char seed[SEEDBYTES],
                      unsigned char nonce)
{
    EtaScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    for (unsigned int i = 0; i < SEEDBYTES; ++i) {
        scratch.inbuf[i] = seed[i];
    }
    scratch.inbuf[SEEDBYTES] = nonce;

    shake256_absorb(scratch.state, scratch.inbuf, SEEDBYTES + 1);
    shake256_squeezeblocks(scratch.outbuf, 2, scratch.state);
    const unsigned int count = reject_eta(output->coeffs,
                                          N,
                                          scratch.outbuf,
                                          2 * SHAKE256_RATE);
    if (count < N) {
        shake256_squeezeblocks(scratch.outbuf, 1, scratch.state);
        reject_eta(output->coeffs + count,
                   N - count,
                   scratch.outbuf,
                   SHAKE256_RATE);
    }
}

void poly_uniform_gamma1m1(
    poly* output,
    const unsigned char seed[SEEDBYTES + CRHBYTES],
    std::uint16_t nonce)
{
    GammaScratch scratch{};
    qrllib::secure_memory::RangeWipeGuard wipe(&scratch, sizeof(scratch));
    for (unsigned int i = 0; i < SEEDBYTES + CRHBYTES; ++i) {
        scratch.inbuf[i] = seed[i];
    }
    scratch.inbuf[SEEDBYTES + CRHBYTES] = nonce & 0xff;
    scratch.inbuf[SEEDBYTES + CRHBYTES + 1] = nonce >> 8;

    shake256_absorb(scratch.state,
                    scratch.inbuf,
                    SEEDBYTES + CRHBYTES + 2);
    shake256_squeezeblocks(scratch.outbuf, 5, scratch.state);
    const unsigned int count = reject_gamma1m1(output->coeffs,
                                               N,
                                               scratch.outbuf,
                                               5 * SHAKE256_RATE);
    if (count < N) {
        shake256_squeezeblocks(scratch.outbuf, 1, scratch.state);
        reject_gamma1m1(output->coeffs + count,
                        N - count,
                        scratch.outbuf,
                        SHAKE256_RATE);
    }
}

void polyvecl_pointwise_acc_invmontgomery(poly* output,
                                          const polyvecl* left,
                                          const polyvecl* right)
{
    poly temporary{};
    qrllib::secure_memory::RangeWipeGuard wipe(&temporary,
                                                sizeof(temporary));
    poly_pointwise_invmontgomery(output, left->vec, right->vec);
    for (unsigned int i = 1; i < L; ++i) {
        poly_pointwise_invmontgomery(&temporary,
                                     left->vec + i,
                                     right->vec + i);
        poly_add(output, output, &temporary);
    }
    for (unsigned int i = 0; i < N; ++i) {
        output->coeffs[i] = reduce32(output->coeffs[i]);
    }
}

void polyeta_pack(unsigned char* output, const poly* input)
{
#if ETA > 7
#error "polyeta_pack assumes ETA <= 7"
#endif
    unsigned char temporary[8]{};
    qrllib::secure_memory::RangeWipeGuard wipe(temporary,
                                                sizeof(temporary));
#if ETA <= 3
    for (unsigned int i = 0; i < N / 8; ++i) {
        temporary[0] = Q + ETA - input->coeffs[8 * i + 0];
        temporary[1] = Q + ETA - input->coeffs[8 * i + 1];
        temporary[2] = Q + ETA - input->coeffs[8 * i + 2];
        temporary[3] = Q + ETA - input->coeffs[8 * i + 3];
        temporary[4] = Q + ETA - input->coeffs[8 * i + 4];
        temporary[5] = Q + ETA - input->coeffs[8 * i + 5];
        temporary[6] = Q + ETA - input->coeffs[8 * i + 6];
        temporary[7] = Q + ETA - input->coeffs[8 * i + 7];

        output[3 * i + 0] = temporary[0];
        output[3 * i + 0] |= temporary[1] << 3;
        output[3 * i + 0] |= temporary[2] << 6;
        output[3 * i + 1] = temporary[2] >> 2;
        output[3 * i + 1] |= temporary[3] << 1;
        output[3 * i + 1] |= temporary[4] << 4;
        output[3 * i + 1] |= temporary[5] << 7;
        output[3 * i + 2] = temporary[5] >> 1;
        output[3 * i + 2] |= temporary[6] << 2;
        output[3 * i + 2] |= temporary[7] << 5;
    }
#else
    for (unsigned int i = 0; i < N / 2; ++i) {
        temporary[0] = static_cast<unsigned char>(
            Q + ETA - input->coeffs[2 * i + 0]);
        temporary[1] = static_cast<unsigned char>(
            Q + ETA - input->coeffs[2 * i + 1]);
        output[i] = static_cast<unsigned char>(
            temporary[0] | (temporary[1] << 4));
    }
#endif
}

void polyt0_pack(unsigned char* output, const poly* input)
{
    std::uint32_t temporary[4]{};
    qrllib::secure_memory::RangeWipeGuard wipe(temporary,
                                                sizeof(temporary));
    for (unsigned int i = 0; i < N / 4; ++i) {
        temporary[0] = Q + (1 << (D - 1)) - input->coeffs[4 * i + 0];
        temporary[1] = Q + (1 << (D - 1)) - input->coeffs[4 * i + 1];
        temporary[2] = Q + (1 << (D - 1)) - input->coeffs[4 * i + 2];
        temporary[3] = Q + (1 << (D - 1)) - input->coeffs[4 * i + 3];

        output[7 * i + 0] = static_cast<unsigned char>(temporary[0]);
        output[7 * i + 1] =
            static_cast<unsigned char>(temporary[0] >> 8);
        output[7 * i + 1] |= temporary[1] << 6;
        output[7 * i + 2] =
            static_cast<unsigned char>(temporary[1] >> 2);
        output[7 * i + 3] =
            static_cast<unsigned char>(temporary[1] >> 10);
        output[7 * i + 3] |= temporary[2] << 4;
        output[7 * i + 4] =
            static_cast<unsigned char>(temporary[2] >> 4);
        output[7 * i + 5] =
            static_cast<unsigned char>(temporary[2] >> 12);
        output[7 * i + 5] |= temporary[3] << 2;
        output[7 * i + 6] =
            static_cast<unsigned char>(temporary[3] >> 6);
    }
}

void polyz_pack(unsigned char* output, const poly* input)
{
#if GAMMA1 > (1 << 19)
#error "polyz_pack assumes GAMMA1 <= 2^19"
#endif
    std::uint32_t temporary[2]{};
    qrllib::secure_memory::RangeWipeGuard wipe(temporary,
                                                sizeof(temporary));
    for (unsigned int i = 0; i < N / 2; ++i) {
        temporary[0] = GAMMA1 - 1 - input->coeffs[2 * i + 0];
        temporary[0] += static_cast<std::uint32_t>(
            static_cast<std::int32_t>(temporary[0]) >> 31) & Q;
        temporary[1] = GAMMA1 - 1 - input->coeffs[2 * i + 1];
        temporary[1] += static_cast<std::uint32_t>(
            static_cast<std::int32_t>(temporary[1]) >> 31) & Q;

        output[5 * i + 0] = static_cast<unsigned char>(temporary[0]);
        output[5 * i + 1] =
            static_cast<unsigned char>(temporary[0] >> 8);
        output[5 * i + 2] =
            static_cast<unsigned char>(temporary[0] >> 16);
        output[5 * i + 2] |= temporary[1] << 4;
        output[5 * i + 3] =
            static_cast<unsigned char>(temporary[1] >> 4);
        output[5 * i + 4] =
            static_cast<unsigned char>(temporary[1] >> 12);
    }
}
