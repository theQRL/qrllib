// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
/* Based on the public domain implementations attributed in
 * deps/kyber/ref/fips202.c. */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include <crypto/secure_memory.h>
#include <kyber/ref/fips202.h>

void KeccakF1600_StatePermute(uint64_t* state);

namespace {

constexpr unsigned int kRounds = 24;

constexpr uint64_t kRoundConstants[kRounds] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

constexpr unsigned int kRho[kRounds] = {
    1, 3, 6, 10, 15, 21, 28, 36,
    45, 55, 2, 14, 27, 41, 56, 8,
    25, 43, 62, 18, 39, 61, 20, 44
};

constexpr unsigned int kPi[kRounds] = {
    10, 7, 11, 17, 18, 3, 5, 16,
    8, 21, 24, 4, 15, 23, 19, 13,
    12, 2, 20, 14, 22, 9, 6, 1
};

inline uint64_t rotate_left(uint64_t value, unsigned int offset) noexcept
{
    return (value << offset) | (value >> (64 - offset));
}

inline uint64_t read_lane(const volatile uint64_t* lanes,
                          unsigned int index) noexcept
{
    return lanes[index];
}

inline void write_lane(volatile uint64_t* lanes,
                       unsigned int index,
                       uint64_t value) noexcept
{
    lanes[index] = value;
}

uint64_t load64(const unsigned char* input) noexcept
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(input[i]) << (8 * i);
    }
    return value;
}

void store64(unsigned char* output, uint64_t value) noexcept
{
    for (unsigned int i = 0; i < 8; ++i) {
        output[i] = static_cast<unsigned char>(value >> (8 * i));
    }
}

void keccak_absorb(uint64_t* state,
                   unsigned int rate,
                   const unsigned char* input,
                   unsigned long long input_length,
                   unsigned char suffix)
{
    unsigned char block[SHAKE128_RATE]{};
    qrllib::secure_memory::RangeWipeGuard block_guard(block, sizeof(block));
    volatile uint64_t* const lanes = state;

    for (unsigned int i = 0; i < 25; ++i) {
        write_lane(lanes, i, 0);
    }

    while (input_length >= rate) {
        for (unsigned int i = 0; i < rate / 8; ++i) {
            write_lane(lanes, i,
                       read_lane(lanes, i) ^ load64(input + 8 * i));
        }
        KeccakF1600_StatePermute(state);
        input += rate;
        input_length -= rate;
    }

    const auto remaining = static_cast<std::size_t>(input_length);
    if (remaining != 0) {
        std::memcpy(block, input, remaining);
    }
    block[remaining] = suffix;
    block[rate - 1] |= 0x80;
    for (unsigned int i = 0; i < rate / 8; ++i) {
        write_lane(lanes, i,
                   read_lane(lanes, i) ^ load64(block + 8 * i));
    }
}

void keccak_squeezeblocks(unsigned char* output,
                          unsigned long long blocks,
                          uint64_t* state,
                          unsigned int rate)
{
    volatile uint64_t* const lanes = state;
    while (blocks != 0) {
        KeccakF1600_StatePermute(state);
        for (unsigned int i = 0; i < rate / 8; ++i) {
            store64(output + 8 * i, read_lane(lanes, i));
        }
        output += rate;
        --blocks;
    }
}

}  // namespace

#if defined(_MSC_VER)
#define QRLLIB_KECCAK_NOINLINE __declspec(noinline)
#define QRLLIB_KECCAK_BARRIER() _ReadWriteBarrier()
#elif defined(__GNUC__) || defined(__clang__)
#define QRLLIB_KECCAK_NOINLINE __attribute__((noinline))
#define QRLLIB_KECCAK_BARRIER() __asm__ __volatile__("" ::: "memory")
#else
#define QRLLIB_KECCAK_NOINLINE
#define QRLLIB_KECCAK_BARRIER() \
    std::atomic_signal_fence(std::memory_order_seq_cst)
#endif

QRLLIB_KECCAK_NOINLINE void KeccakF1600_StatePermute(uint64_t* state)
{
    // Keep a wiped home for the column parities.  The barriers bound each
    // phase's live values; recheck optimized output when changing compilers to
    // ensure that no anonymous, uncleansed spill slots have appeared.
    uint64_t workspace[5]{};
    qrllib::secure_memory::RangeWipeGuard workspace_guard(workspace,
                                                          sizeof(workspace));

    for (unsigned int round = 0; round < kRounds; ++round) {
        for (unsigned int column = 0; column < 5; ++column) {
            workspace[column] = state[column]
                                ^ state[column + 5]
                                ^ state[column + 10]
                                ^ state[column + 15]
                                ^ state[column + 20];
        }
        QRLLIB_KECCAK_BARRIER();
        for (unsigned int column = 0; column < 5; ++column) {
            const uint64_t mix = workspace[(column + 4) % 5]
                                 ^ rotate_left(workspace[(column + 1) % 5], 1);
            for (unsigned int lane = column; lane < 25; lane += 5) {
                state[lane] ^= mix;
            }
        }
        QRLLIB_KECCAK_BARRIER();

        uint64_t current = state[1];
        for (unsigned int lane = 0; lane < kRounds; ++lane) {
            const unsigned int destination = kPi[lane];
            const uint64_t next = state[destination];
            state[destination] = rotate_left(current, kRho[lane]);
            current = next;
        }
        QRLLIB_KECCAK_BARRIER();

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
            QRLLIB_KECCAK_BARRIER();
        }

        state[0] ^= kRoundConstants[round];
        QRLLIB_KECCAK_BARRIER();
    }
}

#undef QRLLIB_KECCAK_NOINLINE
#undef QRLLIB_KECCAK_BARRIER

void shake128_absorb(uint64_t* state,
                     const unsigned char* input,
                     unsigned int input_length)
{
    keccak_absorb(state, SHAKE128_RATE, input, input_length, 0x1f);
}

void shake128_squeezeblocks(unsigned char* output,
                            unsigned long long blocks,
                            uint64_t* state)
{
    keccak_squeezeblocks(output, blocks, state, SHAKE128_RATE);
}

void shake256(unsigned char* output,
              unsigned long long output_length,
              const unsigned char* input,
              unsigned long long input_length)
{
    uint64_t state[25]{};
    qrllib::secure_memory::RangeWipeGuard state_guard(state, sizeof(state));
    unsigned char block[SHAKE256_RATE]{};
    qrllib::secure_memory::RangeWipeGuard block_guard(block, sizeof(block));

    const auto blocks = output_length / SHAKE256_RATE;
    keccak_absorb(state, SHAKE256_RATE, input, input_length, 0x1f);
    keccak_squeezeblocks(output, blocks, state, SHAKE256_RATE);

    const auto produced = blocks * SHAKE256_RATE;
    output_length -= produced;
    if (output_length != 0) {
        output += produced;
        keccak_squeezeblocks(block, 1, state, SHAKE256_RATE);
        std::memcpy(output, block, static_cast<std::size_t>(output_length));
    }
}

void sha3_256(unsigned char* output,
              const unsigned char* input,
              unsigned long long input_length)
{
    uint64_t state[25]{};
    qrllib::secure_memory::RangeWipeGuard state_guard(state, sizeof(state));
    unsigned char block[SHA3_256_RATE]{};
    qrllib::secure_memory::RangeWipeGuard block_guard(block, sizeof(block));

    keccak_absorb(state, SHA3_256_RATE, input, input_length, 0x06);
    keccak_squeezeblocks(block, 1, state, SHA3_256_RATE);
    std::memcpy(output, block, 32);
}

void sha3_512(unsigned char* output,
              const unsigned char* input,
              unsigned long long input_length)
{
    uint64_t state[25]{};
    qrllib::secure_memory::RangeWipeGuard state_guard(state, sizeof(state));
    unsigned char block[SHA3_512_RATE]{};
    qrllib::secure_memory::RangeWipeGuard block_guard(block, sizeof(block));

    keccak_absorb(state, SHA3_512_RATE, input, input_length, 0x06);
    keccak_squeezeblocks(block, 1, state, SHA3_512_RATE);
    std::memcpy(output, block, 64);
}
