// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
xmss_fast.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef XMSSALT_XMSS_FAST_H
#define XMSSALT_XMSS_FAST_H

#include <cstddef>
#include "wots.h"
#include "xmss_common.h"

typedef struct {
    unsigned int h;
    unsigned int next_idx;
    unsigned int stackusage;
    unsigned char completed;
    unsigned char *node;
} treehash_inst;

typedef struct {
    unsigned char *stack;
    unsigned int stackoffset;
    unsigned char *stacklevels;
    unsigned char *auth;
    unsigned char *keep;
    treehash_inst *treehash;
    unsigned char *retain;
    unsigned int next_leaf;
} bds_state;

/**
 * Initialize BDS state struct
 * parameter names are the same as used in the description of the BDS traversal
 */
void xmss_set_bds_state(bds_state *state,
                        unsigned char *stack,
                        unsigned int stackoffset,
                        unsigned char *stacklevels,
                        unsigned char *auth,
                        unsigned char *keep,
                        treehash_inst *treehash,
                        unsigned char *retain,
                        unsigned int next_leaf);

/**
 * Initialize xmssmt_params struct
 * parameter names are the same as in the draft
 * 
 * Especially h is the total tree height, i.e. the XMSS trees have height h/d
 */
/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssfast_Genkeypair(eHashFunction hash_func,
                        xmss_params *params,            // TODO: Refactor this. Remove params, etc.
                        unsigned char *pk,
                        unsigned char *sk,
                        bds_state *state,
                        unsigned char *seed);

/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmssfast_Signmsg(eHashFunction hash_func,
                     xmss_params *params,
                     unsigned char *sk,
                     bds_state *state,
                     unsigned char *sig_msg,
                     unsigned char *msg,
                     unsigned long long msglen);

int xmssfast_update(eHashFunction hash_func,
                    xmss_params *params,
                    unsigned char *sk,
                    bds_state *state,
                    uint32_t new_idx);

#endif // XMSSALT_XMSS_FAST_H
