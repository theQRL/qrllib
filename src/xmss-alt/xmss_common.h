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
#include "xmss_params.h"
#include "eHashFunctions.h"

void xmss_set_params(xmss_params *params, uint32_t n, uint32_t h, uint32_t w, uint32_t k);

bool xmss_hash_function_is_valid(eHashFunction hash_func);
bool xmss_wots_params_are_valid(const wots_params *params);
bool xmss_params_are_valid(const xmss_params *params);


void to_byte(unsigned char *output, unsigned long long in, uint32_t bytes);

// void hexdump(const unsigned char *a, size_t len);  # Unimplemented

void l_tree(eHashFunction hash_func,
            const wots_params *params,
            unsigned char *leaf,
            unsigned char *wots_pk,
            const unsigned char *pub_seed,
            uint32_t addr[8]);

/**
 * Verifies a given message signature pair under a given public key.
 *
 * msg/msglen and sig_msg are detached verification inputs.
 */

int xmss_Verifysig(eHashFunction hash_func,
                   wots_params *wotsParams,
                   const unsigned char *msg,
                   size_t msglen,
                   unsigned char *sig_msg,
                   const unsigned char *pk,
                   unsigned char h);

#endif
