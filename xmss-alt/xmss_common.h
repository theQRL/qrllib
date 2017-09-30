// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
xmss_commons.h 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <cstdlib>
#include <cstdint>
#include "wots.h"

typedef struct{
    unsigned int level;
    unsigned long long subtree;
    unsigned int subleaf;
} leafaddr;

typedef struct{
    wots_params wots_par;
    uint32_t n;
    uint32_t h;
    uint32_t k;
} xmss_params;


void to_byte(unsigned char *output, unsigned long long in, uint32_t bytes);

void hexdump(const unsigned char *a, size_t len);

void xmss_set_params(xmss_params *params, uint32_t n, uint32_t h, uint32_t w, uint32_t k);

void l_tree(unsigned char *leaf,
           unsigned char *wots_pk,
           const xmss_params *params,
           const unsigned char *pub_seed,
           uint32_t addr[8]);

/**
 * Verifies a given message signature pair under a given public key.
 *
 * Note: msg and msglen are pure outputs which carry the message in case verification succeeds. The (input) message is assumed to be within sig_msg which has the form (sig||msg).
 */

int xmss_Verifysig(unsigned char *msg,
                   size_t msglen,
                   unsigned char *sig_msg,
                   const unsigned char *pk,
                   unsigned char h);

#endif
