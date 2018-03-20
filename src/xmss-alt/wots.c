// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
wots.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include <cmath>
#include <cstdint>
#include "xmss_common.h"
#include "hash.h"
#include "hash_address.h"


void wots_set_params(wots_params *params, int n, int w) {
    params->n = n;
    params->w = w;
    params->log_w = (int) log2(w);
    params->len_1 = (int) ceil(((8 * n) / params->log_w));
    params->len_2 = (int) floor(log2(params->len_1 * (w - 1)) / params->log_w) + 1;
    params->len = params->len_1 + params->len_2;
    params->keysize = params->len * params->n;
}

/**
 * Helper method for pseudorandom key generation
 * Expands an n-byte array into a len*n byte array
 * this is done using PRF
 */
void expand_seed(eHashFunction hash_func,
                 unsigned char *outseeds,
                 const unsigned char *inseed,
                 const uint32_t n,
                 const uint32_t len) {
    unsigned char ctr[32];
    for (uint32_t i = 0; i < len; i++) {
        to_byte(ctr, i, 32);
        prf(hash_func, (outseeds + (i * n)), ctr, inseed, n);
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays
 *
 * interpretes in as start-th value of the chain
 * addr has to contain the address of the chain
 */
void gen_chain(eHashFunction hash_func,
               unsigned char *out,
               const unsigned char *in,
               unsigned int start,
               unsigned int steps,
               const wots_params *params,
               const unsigned char *pub_seed,
               uint32_t addr[8]) {
    uint32_t i, j;
    for (j = 0; j < params->n; j++)
        out[j] = in[j];

    for (i = start; i < (start + steps) && i < params->w; i++) {
        setHashADRS(addr, i);
        hash_f(hash_func, out, out, pub_seed, addr, params->n);
    }
}

/**
 * base_w algorithm as described in draft.
 *
 *
 */
void base_w(int *output,
            const int out_len,
            const unsigned char *input,
            const wots_params *params) {
    int in = 0;
    int out = 0;
    uint32_t total = 0;
    int bits = 0;
    int consumed = 0;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= params->log_w;
        output[out] = (total >> bits) & (params->w - 1);
        out++;
    }
}

void wots_pkgen(eHashFunction hash_func,
                unsigned char *pk,
                const unsigned char *sk,
                const wots_params *params,
                const unsigned char *pub_seed,
                uint32_t addr[8]) {
    uint32_t i;
    expand_seed(hash_func, pk, sk, params->n, params->len);
    for (i = 0; i < params->len; i++) {
        setChainADRS(addr, i);
        gen_chain(hash_func,
                  pk + i * params->n,
                  pk + i * params->n,
                  0,
                  params->w - 1,
                  params,
                  pub_seed,
                  addr);
    }
}


void wots_sign(eHashFunction hash_func,
               unsigned char *sig,
               const unsigned char *msg,
               const unsigned char *sk,
               const wots_params *params,
               const unsigned char *pub_seed,
               uint32_t addr[8]) {
    int basew[params->len];
    int csum = 0;
    uint32_t i = 0;

    base_w(basew, params->len_1, msg, params);

    for (i = 0; i < params->len_1; i++) {
        csum += params->w - 1 - basew[i];
    }

    csum = csum << (8 - ((params->len_2 * params->log_w) % 8));

    uint32_t len_2_bytes = ((params->len_2 * params->log_w) + 7) / 8;

    unsigned char csum_bytes[len_2_bytes];
    to_byte(csum_bytes, csum, len_2_bytes);

    int csum_basew[params->len_2];

    base_w(csum_basew, params->len_2, csum_bytes, params);

    for (i = 0; i < params->len_2; i++) {
        basew[params->len_1 + i] = csum_basew[i];
    }

    expand_seed(hash_func, sig, sk, params->n, params->len);

    for (i = 0; i < params->len; i++) {
        setChainADRS(addr, i);
        gen_chain(hash_func, sig + i * params->n, sig + i * params->n, 0, basew[i], params, pub_seed, addr);
    }
}

void wots_pkFromSig(eHashFunction hash_func,
                    unsigned char *pk,
                    const unsigned char *sig,
                    const unsigned char *msg,
                    const wots_params *wotsParams,
                    const unsigned char *pub_seed,
                    uint32_t addr[8]) {
    uint32_t XMSS_WOTS_LEN = wotsParams->len;
    uint32_t XMSS_WOTS_LEN1 = wotsParams->len_1;
    uint32_t XMSS_WOTS_LEN2 = wotsParams->len_2;
    uint32_t XMSS_WOTS_LOG_W = wotsParams->log_w;
    uint32_t XMSS_WOTS_W = wotsParams->w;
    uint32_t XMSS_N = wotsParams->n;

    int basew[XMSS_WOTS_LEN];
    int csum = 0;
    unsigned char csum_bytes[((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) + 7) / 8];
    int csum_basew[XMSS_WOTS_LEN2];
    uint32_t i = 0;

    base_w(basew, XMSS_WOTS_LEN1, msg, wotsParams);

    for (i = 0; i < XMSS_WOTS_LEN1; i++) {
        csum += XMSS_WOTS_W - 1 - basew[i];
    }

    csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));

    to_byte(csum_bytes, csum, ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) + 7) / 8);
    base_w(csum_basew, XMSS_WOTS_LEN2, csum_bytes, wotsParams);

    for (i = 0; i < XMSS_WOTS_LEN2; i++) {
        basew[XMSS_WOTS_LEN1 + i] = csum_basew[i];
    }
    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        setChainADRS(addr, i);
        gen_chain(hash_func,
                  pk + i * XMSS_N, sig + i * XMSS_N,
                  basew[i], XMSS_WOTS_W - 1 - basew[i], wotsParams, pub_seed, addr);
    }
}
