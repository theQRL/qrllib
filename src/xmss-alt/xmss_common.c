// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
xmss_commons.c 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "xmss_common.h"
#include "hash_address.h"
#include "hash.h"
#include <cstdio>
#include <cstring>

void to_byte(unsigned char *out, unsigned long long in, uint32_t bytes) {
    int32_t i;
    for (i = bytes - 1; i >= 0; i--) {
        out[i] = static_cast<unsigned char>(in & 0xff);
        in = in >> 8;
    }
}

/**
 * Initialize xmss params struct
 * parameter names are the same as in the draft
 */
void xmss_set_params(xmss_params *params, uint32_t n, uint32_t h, uint32_t w, uint32_t k) {
    if (k >= h || k < 2 || (h - k) % 2) {
        fprintf(stderr, "For BDS traversal, H - K must be even, with H > K >= 2!\n");
        return;
    }

    params->h = h;
    params->n = n;
    params->k = k;

    wots_params wots_par;
    wots_set_params(&wots_par, n, w);
    params->wots_par = wots_par;
}

void l_tree(eHashFunction hash_func,
            const wots_params *params,
            unsigned char *leaf,
            unsigned char *wots_pk,
            const unsigned char *pub_seed,
            uint32_t addr[8]) {
    unsigned int l = params->len;
    unsigned int n = params->n;
    uint32_t i = 0;
    uint32_t height = 0;
    uint32_t bound;

    setTreeHeight(addr, height);

    while (l > 1) {
        bound = l >> 1;
        for (i = 0; i < bound; i++) {
            setTreeIndex(addr, i);
            hash_h(hash_func, wots_pk + i * n, wots_pk + i * 2 * n, pub_seed, addr, n);
        }
        if (l & 1) {
            memcpy(wots_pk + (l >> 1) * n, wots_pk + (l - 1) * n, n);
            l = (l >> 1) + 1;
        } else {
            l = (l >> 1);
        }
        height++;
        setTreeHeight(addr, height);
    }
    memcpy(leaf, wots_pk, n);
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void
validate_authpath(eHashFunction hash_func,
                  unsigned char *root,
                  const unsigned char *leaf,
                  unsigned long leafidx,
                  const unsigned char *authpath,
                  const uint32_t n,
                  const uint32_t h,
                  const unsigned char *pub_seed,
                  uint32_t addr[8]) {
    uint32_t i, j;
    unsigned char buffer[2 * n];

    // If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
    // Otherwise, it is the other way around
    if (leafidx & 1) {
        for (j = 0; j < n; j++)
            buffer[n + j] = leaf[j];
        for (j = 0; j < n; j++)
            buffer[j] = authpath[j];
    } else {
        for (j = 0; j < n; j++)
            buffer[j] = leaf[j];
        for (j = 0; j < n; j++)
            buffer[n + j] = authpath[j];
    }
    authpath += n;

    for (i = 0; i < h - 1; i++) {
        setTreeHeight(addr, i);
        leafidx >>= 1;
        setTreeIndex(addr, leafidx);
        if (leafidx & 1) {
            hash_h(hash_func, buffer + n, buffer, pub_seed, addr, n);
            for (j = 0; j < n; j++)
                buffer[j] = authpath[j];
        } else {
            hash_h(hash_func, buffer, buffer, pub_seed, addr, n);
            for (j = 0; j < n; j++)
                buffer[j + n] = authpath[j];
        }
        authpath += n;
    }
    setTreeHeight(addr, (h - 1));
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    hash_h(hash_func, root, buffer, pub_seed, addr, n);
}


/**
 * Verifies a given message signature pair under a given public key.
 */
int xmss_Verifysig(eHashFunction hash_func,
                   wots_params *wotsParams,
                   unsigned char *msg,
                   const size_t msglen,
                   unsigned char *sig_msg,
                   const unsigned char *pk,
                   unsigned char h) {

    auto sig_msg_len = static_cast<unsigned long long int>(4 + 32 + 67 * 32 + h * 32);

    uint32_t n = wotsParams->n;

    unsigned long long i, m_len;
    unsigned long idx = 0;
    unsigned char wots_pk[wotsParams->keysize];
    unsigned char pkhash[n];
    unsigned char root[n];
    unsigned char msg_h[n];
    unsigned char hash_key[3 * n];

    unsigned char pub_seed[n];
    memcpy(pub_seed, pk + n, n);

    // Init addresses
    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t ltree_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t node_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    setType(ots_addr, 0);
    setType(ltree_addr, 1);
    setType(node_addr, 2);

    // Extract index
    idx = ((unsigned long) sig_msg[0] << 24) |
          ((unsigned long) sig_msg[1] << 16) |
          ((unsigned long) sig_msg[2] << 8) |
          sig_msg[3];

    // printf("verify:: idx = %lu\n", idx);

    // Generate hash key (R || root || idx)
    memcpy(hash_key, sig_msg + 4, n);
    memcpy(hash_key + n, pk, n);
    to_byte(hash_key + 2 * n, idx, n);

    sig_msg += (n + 4);
    sig_msg_len -= (n + 4);

    // hash message
    unsigned long long tmp_sig_len = wotsParams->keysize + h * n;
    m_len = sig_msg_len - tmp_sig_len;
    //h_msg(msg_h, sig_msg + tmp_sig_len, m_len, hash_key, 3*n, n);
    h_msg(hash_func, msg_h, msg, msglen, hash_key, 3 * n, n);
    //-----------------------
    // Verify signature
    //-----------------------

    // Prepare Address
    setOTSADRS(ots_addr, idx);
    // Check WOTS signature
    wots_pkFromSig(hash_func, wots_pk, sig_msg, msg_h, wotsParams, pub_seed, ots_addr);

    sig_msg += wotsParams->keysize;
    sig_msg_len -= wotsParams->keysize;

    // Compute Ltree
    setLtreeADRS(ltree_addr, idx);
    l_tree(hash_func, wotsParams, pkhash, wots_pk, pub_seed, ltree_addr);

    // Compute root
    validate_authpath(hash_func, root, pkhash, idx, sig_msg, n, h, pub_seed, node_addr);

    sig_msg += h * n;
    sig_msg_len -= h * n;

    for (i = 0; i < n; i++)
        if (root[i] != pk[i])
            goto fail;

    for (i = 0; i < sig_msg_len; i++)
        msg[i] = sig_msg[i];

    return 0;

    fail:
    for (i = 0; i < sig_msg_len; i++)
        msg[i] = 0;
    return -1;
}
