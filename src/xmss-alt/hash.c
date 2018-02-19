// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
/*
This code was taken from the XMSS reference implementation by Andreas Hülsing and Joost Rijneveld and is public domain.
*/

#include "hash_address.h"
#include "xmss_common.h"
#include "hash.h"
#include "fips202.h"
#include "shasha.h"
#include <cstdio>

unsigned char *addr_to_byte(unsigned char *bytes, const uint32_t addr[8]) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    int i = 0;
    for (i = 0; i < 8; i++)
        to_byte(bytes + i * 4, addr[i], 4);
    return bytes;
#else
    memcpy(bytes, addr, 32);
    return bytes;
#endif
}

int core_hash(eHashFunction hash_func,
              unsigned char *out,
              const unsigned int type,
              const unsigned char *key,
              unsigned int keylen,
              const unsigned char *in,
              unsigned long long inlen,
              unsigned int n) {
    unsigned long long i = 0;
    unsigned char buf[inlen + n + keylen];

    // Input is (toByte(X, 32) || KEY || M)

    // set toByte
    to_byte(buf, type, n);

    for (i = 0; i < keylen; i++) {
        buf[i + n] = key[i];
    }

    for (i = 0; i < inlen; i++) {
        buf[keylen + n + i] = in[i];
    }

    if (hash_func==eHashFunction::SHAKE_128)
    {
        if (n == 32) {
            shake128(out, 32, buf, inlen + keylen + n);
            return 0;
        }

        if (n == 64) {
            shake128(out, 64, buf, inlen + keylen + n);
            return 0;
        }
    }

    if (hash_func==eHashFunction::SHAKE_256)
    {
        if (n == 32) {
            shake256(out, 32, buf, inlen + keylen + n);
            return 0;
        }

        if (n == 64) {
            shake256(out, 64, buf, inlen + keylen + n);
            return 0;
        }
    }

    if (hash_func==eHashFunction::SHA2_256)
    {
        if (n == 32) {
            sha2_256(out, buf, inlen + keylen + n);
            return 0;
        }
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

    unsigned char buf[2 * n];
    unsigned char key[n];
    unsigned char bitmask[2 * n];
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
    unsigned char buf[n];
    unsigned char key[n];
    unsigned char bitmask[n];
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
