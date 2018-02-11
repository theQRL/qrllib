#ifndef WOTS_PARAMS_H
#define WOTS_PARAMS_H

/**
 * WOTS parameter set
 *
 * Meaning as defined in draft-irtf-cfrg-xmss-hash-based-signatures-02
 */
// FIXME: Get rid of this
typedef struct {
    uint32_t len_1;
    uint32_t len_2;
    uint32_t len;
    uint32_t n;
    uint32_t w;
    uint32_t log_w;
    uint32_t keysize;
} wots_params;

/**
 * Set the WOTS parameters,
 * only m, n, w are required as inputs,
 * len, len_1, and len_2 are computed from those.
 *
 * Assumes w is a power of 2
 */
void wots_set_params(wots_params *params, int n, int w);

#endif