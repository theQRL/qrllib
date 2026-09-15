// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer 
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#include <atomic>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#include "fips202.h"
#include <crypto/secure_memory.h>

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64-(offset))))

#if defined(_MSC_VER)
#define QRLLIB_COMPILER_BARRIER() _ReadWriteBarrier()
#elif defined(__GNUC__) || defined(__clang__)
#define QRLLIB_COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")
#else
#define QRLLIB_COMPILER_BARRIER() \
    std::atomic_signal_fence(std::memory_order_seq_cst)
#endif

static uint64_t load64(const unsigned char *x) {
    unsigned long long r = 0, i;

    for (i = 0; i < 8; ++i) {
        r |= (unsigned long long) x[i] << 8 * i;
    }
    return r;
}

static void store64(uint8_t *x, uint64_t u) {
    unsigned int i;

    for (i = 0; i < 8; ++i) {
        x[i] = static_cast<uint8_t>(u);
        u >>= 8;
    }
}

static const uint64_t KeccakF_RoundConstants[NROUNDS] =
        {
                (uint64_t) 0x0000000000000001ULL,
                (uint64_t) 0x0000000000008082ULL,
                (uint64_t) 0x800000000000808aULL,
                (uint64_t) 0x8000000080008000ULL,
                (uint64_t) 0x000000000000808bULL,
                (uint64_t) 0x0000000080000001ULL,
                (uint64_t) 0x8000000080008081ULL,
                (uint64_t) 0x8000000000008009ULL,
                (uint64_t) 0x000000000000008aULL,
                (uint64_t) 0x0000000000000088ULL,
                (uint64_t) 0x0000000080008009ULL,
                (uint64_t) 0x000000008000000aULL,
                (uint64_t) 0x000000008000808bULL,
                (uint64_t) 0x800000000000008bULL,
                (uint64_t) 0x8000000000008089ULL,
                (uint64_t) 0x8000000000008003ULL,
                (uint64_t) 0x8000000000008002ULL,
                (uint64_t) 0x8000000000000080ULL,
                (uint64_t) 0x000000000000800aULL,
                (uint64_t) 0x800000008000000aULL,
                (uint64_t) 0x8000000080008081ULL,
                (uint64_t) 0x8000000000008080ULL,
                (uint64_t) 0x0000000080000001ULL,
                (uint64_t) 0x8000000080008008ULL
        };

static const unsigned int KeccakF_RotationOffsets[NROUNDS] =
        {
                1, 3, 6, 10, 15, 21, 28, 36,
                45, 55, 2, 14, 27, 41, 56, 8,
                25, 43, 62, 18, 39, 61, 20, 44
        };

static const unsigned int KeccakF_PiLane[NROUNDS] =
        {
                10, 7, 11, 17, 18, 3, 5, 16,
                8, 21, 24, 4, 15, 23, 19, 13,
                12, 2, 20, 14, 22, 9, 6, 1
        };

#if defined(_MSC_VER)
#define QRLLIB_XMSS_PERMUTE_ATTR __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define QRLLIB_XMSS_PERMUTE_ATTR __attribute__((noinline))
#else
#define QRLLIB_XMSS_PERMUTE_ATTR
#endif

QRLLIB_XMSS_PERMUTE_ATTR void KeccakF1600_StatePermute(uint64_t *state) {
    // Keep a wiped home for the column parities.  The barriers bound each
    // phase's live values; recheck optimized output when changing compilers to
    // ensure that no anonymous, uncleansed spill slots have appeared.
    uint64_t workspace[5]{};
    qrllib::secure_memory::RangeWipeGuard workspace_guard(workspace,
                                                          sizeof(workspace));

    for (unsigned int round = 0; round < NROUNDS; ++round) {
        for (unsigned int column = 0; column < 5; ++column) {
            workspace[column] = state[column] ^ state[column + 5]
                                ^ state[column + 10] ^ state[column + 15]
                                ^ state[column + 20];
        }
        QRLLIB_COMPILER_BARRIER();
        for (unsigned int column = 0; column < 5; ++column) {
            const uint64_t mix = workspace[(column + 4) % 5]
                                 ^ ROL(workspace[(column + 1) % 5], 1);
            for (unsigned int lane = column; lane < 25; lane += 5) {
                state[lane] ^= mix;
            }
        }
        QRLLIB_COMPILER_BARRIER();

        uint64_t current = state[1];
        for (unsigned int lane = 0; lane < NROUNDS; ++lane) {
            const unsigned int destination = KeccakF_PiLane[lane];
            const uint64_t next = state[destination];
            state[destination] = ROL(current,
                                     KeccakF_RotationOffsets[lane]);
            current = next;
        }
        QRLLIB_COMPILER_BARRIER();

        for (unsigned int row = 0; row < 25; row += 5) {
            const uint64_t lane0 = state[row];
            const uint64_t lane1 = state[row + 1];
            const uint64_t lane2 = state[row + 2];
            const uint64_t lane3 = state[row + 3];
            const uint64_t lane4 = state[row + 4];
            state[row] = lane0 ^ ((~lane1) & lane2);
            state[row + 1] = lane1 ^ ((~lane2) & lane3);
            state[row + 2] = lane2 ^ ((~lane3) & lane4);
            state[row + 3] = lane3 ^ ((~lane4) & lane0);
            state[row + 4] = lane4 ^ ((~lane0) & lane1);
            QRLLIB_COMPILER_BARRIER();
        }

        state[0] ^= KeccakF_RoundConstants[round];
        QRLLIB_COMPILER_BARRIER();
    }
}

#undef QRLLIB_XMSS_PERMUTE_ATTR
#undef QRLLIB_COMPILER_BARRIER

static void keccak_squeezeblocks(unsigned char *h, unsigned long long nblocks,
                                 uint64_t *s, unsigned int r) {
    unsigned int i;

    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
        for (i = 0; i < (r >> 3); i++) {
            store64(h + 8 * i, s[i]);
        }
        h += r;
        nblocks--;
    }
}

static void keccak_absorb_segment(uint64_t *state,
                                  unsigned int rate,
                                  unsigned char *block,
                                  unsigned int *used,
                                  const unsigned char *input,
                                  unsigned long long inputlen)
{
    while (inputlen != 0) {
        if (*used == 0 && inputlen >= rate) {
            for (unsigned int i = 0; i < rate / 8; ++i) {
                state[i] ^= load64(input + 8 * i);
            }
            KeccakF1600_StatePermute(state);
            input += rate;
            inputlen -= rate;
            continue;
        }

        const auto available = static_cast<unsigned long long>(rate - *used);
        const auto take = inputlen < available ? inputlen : available;
        std::memcpy(block + *used, input, static_cast<std::size_t>(take));
        *used += static_cast<unsigned int>(take);
        input += take;
        inputlen -= take;

        if (*used == rate) {
            for (unsigned int i = 0; i < rate / 8; ++i) {
                state[i] ^= load64(block + 8 * i);
            }
            KeccakF1600_StatePermute(state);
            std::memset(block, 0, rate);
            *used = 0;
        }
    }
}

static void shake_three(unsigned char *out,
                        unsigned long long outlen,
                        unsigned int rate,
                        const unsigned char *first,
                        unsigned long long firstlen,
                        const unsigned char *second,
                        unsigned long long secondlen,
                        const unsigned char *third,
                        unsigned long long thirdlen)
{
    uint64_t state[25]{};
    qrllib::secure_memory::RangeWipeGuard state_guard(state, sizeof(state));
    unsigned char block[SHAKE128_RATE]{};
    qrllib::secure_memory::RangeWipeGuard block_guard(block, sizeof(block));
    unsigned int used = 0;

    keccak_absorb_segment(state, rate, block, &used, first, firstlen);
    keccak_absorb_segment(state, rate, block, &used, second, secondlen);
    keccak_absorb_segment(state, rate, block, &used, third, thirdlen);

    block[used] = 0x1f;
    block[rate - 1] |= 0x80;
    for (unsigned int i = 0; i < rate / 8; ++i) {
        state[i] ^= load64(block + 8 * i);
    }

    const auto full_blocks = outlen / rate;
    if (full_blocks != 0) {
        keccak_squeezeblocks(out, full_blocks, state, rate);
        out += full_blocks * rate;
    }
    if (outlen % rate != 0) {
        std::memset(block, 0, rate);
        keccak_squeezeblocks(block, 1, state, rate);
        std::memcpy(out, block, static_cast<std::size_t>(outlen % rate));
    }
}

void shake128(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen) {
    shake_three(out, outlen, SHAKE128_RATE,
                in, inlen, nullptr, 0, nullptr, 0);
}

void shake128_3(unsigned char *out,
                unsigned long long outlen,
                const unsigned char *first,
                unsigned long long firstlen,
                const unsigned char *second,
                unsigned long long secondlen,
                const unsigned char *third,
                unsigned long long thirdlen)
{
    shake_three(out, outlen, SHAKE128_RATE,
                first, firstlen, second, secondlen, third, thirdlen);
}

void shake256(unsigned char *output, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen) {
    shake_three(output, outlen, SHAKE256_RATE,
                in, inlen, nullptr, 0, nullptr, 0);
}

void shake256_3(unsigned char *out,
                unsigned long long outlen,
                const unsigned char *first,
                unsigned long long firstlen,
                const unsigned char *second,
                unsigned long long secondlen,
                const unsigned char *third,
                unsigned long long thirdlen)
{
    shake_three(out, outlen, SHAKE256_RATE,
                first, firstlen, second, secondlen, third, thirdlen);
}
