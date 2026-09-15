// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
/*
This code was taken from the XMSS reference implementation by Andreas Hülsing and Joost Rijneveld and is public domain.
*/

#include "hash_address.h"
#include "xmss_common.h"
#include "hash.h"
#include "fips202.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <limits>
#include <crypto/secure_memory.h>

namespace {

constexpr size_t SUPPORTED_HASH_N = 64;

constexpr uint32_t SHA256_INITIAL_STATE[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

constexpr uint32_t SHA256_CONSTANTS[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

inline uint32_t rotate_right(uint32_t value, unsigned int amount)
{
    return (value >> amount) | (value << (32U - amount));
}

void sha256_compress(uint32_t state[8], const unsigned char block[64])
{
    uint32_t schedule[64]{};
    qrllib::secure_memory::RangeWipeGuard schedule_guard(
        schedule, sizeof(schedule));
    for (std::size_t i = 0; i < 16; ++i) {
        schedule[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
                      (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
                      (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
                      static_cast<uint32_t>(block[4 * i + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const uint32_t s0 = rotate_right(schedule[i - 15], 7) ^
                            rotate_right(schedule[i - 15], 18) ^
                            (schedule[i - 15] >> 3);
        const uint32_t s1 = rotate_right(schedule[i - 2], 17) ^
                            rotate_right(schedule[i - 2], 19) ^
                            (schedule[i - 2] >> 10);
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    uint32_t work[8];
    qrllib::secure_memory::RangeWipeGuard work_guard(work, sizeof(work));
    std::memcpy(work, state, sizeof(work));
    for (std::size_t i = 0; i < 64; ++i) {
        const uint32_t sum1 = rotate_right(work[4], 6) ^
                              rotate_right(work[4], 11) ^
                              rotate_right(work[4], 25);
        const uint32_t choose = (work[4] & work[5]) ^
                                (~work[4] & work[6]);
        const uint32_t temp1 = work[7] + sum1 + choose +
                               SHA256_CONSTANTS[i] + schedule[i];
        const uint32_t sum0 = rotate_right(work[0], 2) ^
                              rotate_right(work[0], 13) ^
                              rotate_right(work[0], 22);
        const uint32_t majority = (work[0] & work[1]) ^
                                  (work[0] & work[2]) ^
                                  (work[1] & work[2]);
        const uint32_t temp2 = sum0 + majority;

        work[7] = work[6];
        work[6] = work[5];
        work[5] = work[4];
        work[4] = work[3] + temp1;
        work[3] = work[2];
        work[2] = work[1];
        work[1] = work[0];
        work[0] = temp1 + temp2;
    }
    for (std::size_t i = 0; i < 8; ++i) {
        state[i] += work[i];
    }
}

bool sha256_update(uint32_t state[8],
                   unsigned char block[64],
                   std::size_t& used,
                   uint64_t& total,
                   const unsigned char* input,
                   uint64_t inputlen)
{
    if (inputlen > std::numeric_limits<uint64_t>::max() - total) {
        return false;
    }
    total += inputlen;

    while (inputlen != 0) {
        if (used == 0 && inputlen >= 64) {
            sha256_compress(state, input);
            input += 64;
            inputlen -= 64;
            continue;
        }
        const auto available = static_cast<uint64_t>(64 - used);
        const auto take = inputlen < available ? inputlen : available;
        std::memcpy(block + used, input, static_cast<std::size_t>(take));
        used += static_cast<std::size_t>(take);
        input += take;
        inputlen -= take;
        if (used == 64) {
            sha256_compress(state, block);
            qrllib::secure_memory::secure_zero(block, 64);
            used = 0;
        }
    }
    return true;
}

bool sha256_three(unsigned char out[32],
                  const unsigned char* first,
                  uint64_t firstlen,
                  const unsigned char* second,
                  uint64_t secondlen,
                  const unsigned char* third,
                  uint64_t thirdlen)
{
    uint32_t state[8];
    qrllib::secure_memory::RangeWipeGuard state_guard(state, sizeof(state));
    std::memcpy(state, SHA256_INITIAL_STATE, sizeof(state));
    unsigned char block[64]{};
    qrllib::secure_memory::RangeWipeGuard block_guard(block, sizeof(block));
    std::size_t used = 0;
    uint64_t total = 0;

    if (!sha256_update(state, block, used, total, first, firstlen) ||
        !sha256_update(state, block, used, total, second, secondlen) ||
        !sha256_update(state, block, used, total, third, thirdlen) ||
        total > std::numeric_limits<uint64_t>::max() / 8U) {
        return false;
    }

    block[used++] = 0x80;
    if (used > 56) {
        std::memset(block + used, 0, 64 - used);
        sha256_compress(state, block);
        qrllib::secure_memory::secure_zero(block, 64);
        used = 0;
    }
    std::memset(block + used, 0, 56 - used);
    const uint64_t bit_length = total * 8U;
    for (std::size_t i = 0; i < 8; ++i) {
        block[63 - i] = static_cast<unsigned char>(bit_length >> (8 * i));
    }
    sha256_compress(state, block);

    for (std::size_t i = 0; i < 8; ++i) {
        out[4 * i] = static_cast<unsigned char>(state[i] >> 24);
        out[4 * i + 1] = static_cast<unsigned char>(state[i] >> 16);
        out[4 * i + 2] = static_cast<unsigned char>(state[i] >> 8);
        out[4 * i + 3] = static_cast<unsigned char>(state[i]);
    }
    return true;
}

}  // namespace

int sha2_256_secure(unsigned char *out,
                    const unsigned char *in,
                    unsigned long long inlen)
{
    if (out == nullptr || (in == nullptr && inlen != 0)) {
        return 1;
    }
    return sha256_three(out, in, inlen, nullptr, 0, nullptr, 0) ? 0 : 1;
}

unsigned char *addr_to_byte(unsigned char *bytes, const uint32_t addr[8]) {
    for (int i = 0; i < 8; i++) {
        to_byte(bytes + i * 4, addr[i], 4);
    }
    return bytes;
}

int core_hash(eHashFunction hash_func,
              unsigned char *out,
              const unsigned int type,
              const unsigned char *key,
              unsigned int keylen,
              const unsigned char *in,
              unsigned long long inlen,
              unsigned int n) {
    if (!xmss_hash_function_is_valid(hash_func) || out == nullptr ||
        (key == nullptr && keylen != 0) || (in == nullptr && inlen != 0) ||
        (n != 32 && n != 64)) {
        return 1;
    }

    // Hash the three segments of toByte(type, n) || key || input directly.
    // This keeps stack use constant even when the caller supplies a large
    // message and avoids a second message-sized heap allocation.
    unsigned char prefix[64]{};
    qrllib::secure_memory::RangeWipeGuard prefix_guard(prefix, sizeof(prefix));
    to_byte(prefix, type, n);

    if (hash_func==eHashFunction::SHAKE_128)
    {
        shake128_3(out, n, prefix, n, key, keylen, in, inlen);
        return 0;
    }

    if (hash_func==eHashFunction::SHAKE_256)
    {
        shake256_3(out, n, prefix, n, key, keylen, in, inlen);
        return 0;
    }

    if (hash_func==eHashFunction::SHA2_256 && n == 32) {
        return sha256_three(out, prefix, n, key, keylen, in, inlen) ? 0 : 1;
    }

    return 1;
}

/**
 * Implements PRF
 */
int prf(eHashFunction hash_func,
        unsigned char *out,
        const unsigned char *in,
        const unsigned char *key, unsigned int keylen) {
    return core_hash(hash_func, out, 3, key, keylen, in, 32, keylen);
}

/*
 * Implemts H_msg
 */
int h_msg(eHashFunction hash_func,
          unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *key,
          const unsigned int keylen, const unsigned int n) {
    if (keylen != 3 * n) {
        fprintf(stderr, "H_msg takes 3n-bit keys, we got n=%d but a keylength of %d.\n", n, keylen);
        return 1;
    }
    return core_hash(hash_func, out, 2, key, keylen, in, inlen, n);
}

/**
 * We assume the left half is in in[0]...in[n-1]
 */
int hash_h(eHashFunction hash_func,
           unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8],
           const unsigned int n) {

    if (!xmss_hash_function_is_valid(hash_func) || out == nullptr ||
        in == nullptr || pub_seed == nullptr || addr == nullptr ||
        (n != 32 && n != 64)) {
        return 1;
    }

    unsigned char buf[2 * SUPPORTED_HASH_N];
    unsigned char key[SUPPORTED_HASH_N];
    unsigned char bitmask[2 * SUPPORTED_HASH_N];
    unsigned char byte_addr[32];
    unsigned int i;

    setKeyAndMask(addr, 0);
    addr_to_byte(byte_addr, addr);
    prf(hash_func, key, byte_addr, pub_seed, n);
    // Use MSB order
    setKeyAndMask(addr, 1);
    addr_to_byte(byte_addr, addr);
    prf(hash_func, bitmask, byte_addr, pub_seed, n);
    setKeyAndMask(addr, 2);
    addr_to_byte(byte_addr, addr);
    prf(hash_func, bitmask + n, byte_addr, pub_seed, n);
    for (i = 0; i < 2 * n; i++) {
        buf[i] = in[i] ^ bitmask[i];
    }
    return core_hash(hash_func, out, 1, key, n, buf, 2 * n, n);
}

int hash_f(eHashFunction hash_func,
           unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8],
           const unsigned int n) {
    if (!xmss_hash_function_is_valid(hash_func) || out == nullptr ||
        in == nullptr || pub_seed == nullptr || addr == nullptr ||
        (n != 32 && n != 64)) {
        return 1;
    }

    unsigned char buf[SUPPORTED_HASH_N];
    qrllib::secure_memory::RangeWipeGuard buf_guard(buf, n);
    unsigned char key[SUPPORTED_HASH_N];
    unsigned char bitmask[SUPPORTED_HASH_N];
    unsigned char byte_addr[32];
    unsigned int i;

    setKeyAndMask(addr, 0);
    addr_to_byte(byte_addr, addr);
    prf(hash_func, key, byte_addr, pub_seed, n);

    setKeyAndMask(addr, 1);
    addr_to_byte(byte_addr, addr);
    prf(hash_func, bitmask, byte_addr, pub_seed, n);

    for (i = 0; i < n; i++) {
        buf[i] = in[i] ^ bitmask[i];
    }
    return core_hash(hash_func, out, 0, key, n, buf, n, n);
}
