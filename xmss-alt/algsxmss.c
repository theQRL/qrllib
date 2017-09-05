//Summary of all xmss functions

#include "algsxmss.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "fips202.h"

#include "randombytes.h"
#include "wots.h"
#include "hash.h"
//#include "prg.h"                                                                                 
#include "xmss_commons.h"
#include "hash_address.h"
#include <stdio.h>
#include <fips202.h>

xmss_params params;

/**
 * Initialize xmss params struct
 * parameter names are the same as in the draft
 */
void xmss_set_params(xmss_params *params, int n, int h, int w) {
    params->h = h;
    params->n = n;
    wots_params wots_par;
    wots_set_params(&wots_par, n, w);
    params->wots_par = wots_par;
}

/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes n byte sk_seed and returns n byte seed using 32 byte address addr.
 */
static void get_seed(unsigned char *seed, const unsigned char *sk_seed, int n, uint32_t addr[8]) {
    unsigned char bytes[32];
    // Make sure that chain addr, hash addr, and key bit are 0!
    setChainADRS(addr, 0);
    setHashADRS(addr, 0);
    setKeyAndMask(addr, 0);
    // Generate pseudorandom value
    addr_to_byte(bytes, addr);
    prf(seed, bytes, sk_seed, n);
}

static void
l_tree(unsigned char *leaf, unsigned char *wots_pk, const xmss_params *params, const unsigned char *pub_seed,
       uint32_t addr[8]) {
    unsigned int l = params->wots_par.len;
    unsigned int n = params->n;
    uint32_t i = 0;
    uint32_t height = 0;
    uint32_t bound;

    //ADRS.setTreeHeight(0);
    setTreeHeight(addr, height);

    while (l > 1) {
        bound = l >> 1; //floor(l / 2);
        for (i = 0; i < bound; i++) {
            //ADRS.setTreeIndex(i);
            setTreeIndex(addr, i);
            //wots_pk[i] = RAND_HASH(pk[2i], pk[2i + 1], SEED, ADRS);
            hash_h(wots_pk + i * n, wots_pk + i * 2 * n, pub_seed, addr, n);
        }
        //if ( l % 2 == 1 ) {
        if (l & 1) {
            //pk[floor(l / 2) + 1] = pk[l];
            memcpy(wots_pk + (l >> 1) * n, wots_pk + (l - 1) * n, n);
            //l = ceil(l / 2);
            l = (l >> 1) + 1;
        } else {
            //l = ceil(l / 2);
            l = (l >> 1);
        }
        //ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
        height++;
        setTreeHeight(addr, height);
    }
    //return pk[0];
    memcpy(leaf, wots_pk, n);
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */

static void gen_leaf_wots(unsigned char *leaf, const unsigned char *sk_seed, const xmss_params *params,
                          const unsigned char *pub_seed, uint32_t ltree_addr[8], uint32_t ots_addr[8]) {
    unsigned char seed[params->n];
    unsigned char pk[params->wots_par.keysize];

    get_seed(seed, sk_seed, params->n, ots_addr);
    wots_pkgen(pk, seed, &(params->wots_par), pub_seed, ots_addr);

    l_tree(leaf, pk, params, pub_seed, ltree_addr);
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */

static void
treehash(unsigned char *node,
         uint16_t height,
         uint32_t index,
         const unsigned char *sk_seed,
         const xmss_params *params,
         const unsigned char *pub_seed,
         const uint32_t addr[8]) {

    uint32_t idx = index;
    uint16_t n = params->n;
    // use three different addresses because at this point we use all three formats in parallel
    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
    // only copy layer and tree address parts
    memcpy(ots_addr, addr, 12);
    // type = ots
    setType(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    setType(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    setType(node_addr, 2);

    uint32_t lastnode, i;
    unsigned char stack[(height + 1) * n];
    uint16_t stacklevels[height + 1];
    unsigned int stackoffset = 0;

    lastnode = idx + (1 << height);

    for (; idx < lastnode; idx++) {
        setLtreeADRS(ltree_addr, idx);
        setOTSADRS(ots_addr, idx);
        gen_leaf_wots(stack + stackoffset * n, sk_seed, params, pub_seed, ltree_addr, ots_addr);
        stacklevels[stackoffset] = 0;
        stackoffset++;
        while (stackoffset > 1 && stacklevels[stackoffset - 1] == stacklevels[stackoffset - 2]) {
            setTreeHeight(node_addr, stacklevels[stackoffset - 1]);
            setTreeIndex(node_addr, (idx >> (stacklevels[stackoffset - 1] + 1)));
            hash_h(stack + (stackoffset - 2) * n, stack + (stackoffset - 2) * n, pub_seed,
                   node_addr, n);
            stacklevels[stackoffset - 2]++;
            stackoffset--;
        }
    }
    for (i = 0; i < n; i++)
        node[i] = stack[i];
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void
validate_authpath(unsigned char *root, const unsigned char *leaf, unsigned long leafidx, const unsigned char *authpath,
                  const xmss_params *params, const unsigned char *pub_seed, uint32_t addr[8]) {
    unsigned int n = params->n;

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

    for (i = 0; i < params->h - 1; i++) {
        setTreeHeight(addr, i);
        leafidx >>= 1;
        setTreeIndex(addr, leafidx);
        if (leafidx & 1) {
            hash_h(buffer + n, buffer, pub_seed, addr, n);
            for (j = 0; j < n; j++)
                buffer[j] = authpath[j];
        } else {
            hash_h(buffer, buffer, pub_seed, addr, n);
            for (j = 0; j < n; j++)
                buffer[j + n] = authpath[j];
        }
        authpath += n;
    }
    setTreeHeight(addr, (params->h - 1));
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    hash_h(root, buffer, pub_seed, addr, n);
}

/**
 * Computes the authpath and the root. This method is using a lot of space as we build the whole tree and then select the authpath nodes.
 * For more efficient algorithms see e.g. the chapter on hash-based signatures in Bernstein, Buchmann, Dahmen. "Post-quantum Cryptography", Springer 2009.
 * It returns the authpath in "authpath" with the node on level 0 at index 0.
 */
static void compute_authpath_wots(unsigned char *root, unsigned char *authpath, unsigned long leaf_idx,
                                  const unsigned char *sk_seed, const xmss_params *params, unsigned char *pub_seed,
                                  uint32_t addr[8]) {
    uint32_t i, j, level;
    uint32_t n = params->n;
    uint32_t h = params->h;

    unsigned char tree[2 * (1 << h) * n];

    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];

    memcpy(ots_addr, addr, 12);
    setType(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    setType(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    setType(node_addr, 2);

    // Compute all leaves
    for (i = 0; i < (1U << h); i++) {
        setLtreeADRS(ltree_addr, i);
        setOTSADRS(ots_addr, i);
        gen_leaf_wots(tree + ((1 << h) * n + i * n), sk_seed, params, pub_seed, ltree_addr, ots_addr);
    }


    level = 0;
    // Compute tree:
    // Outer loop: For each inner layer
    for (i = (1 << h); i > 1; i >>= 1) {
        setTreeHeight(node_addr, level);
        // Inner loop: for each pair of sibling nodes
        for (j = 0; j < i; j += 2) {
            setTreeIndex(node_addr, j >> 1);
            hash_h(tree + (i >> 1) * n + (j >> 1) * n, tree + i * n + j * n, pub_seed, node_addr, n);
        }
        level++;
    }

    // copy authpath
    for (i = 0; i < h; i++)
        memcpy(authpath + i * n, tree + ((1 << h) >> i) * n + ((leaf_idx >> i) ^ 1) * n, n);

    // copy root
    memcpy(root, tree + n, n);
}

int xmss_Genkeypair(unsigned char *pk, unsigned char *sk, unsigned char *seed, unsigned char h) {
    // TODO: Remove parameters and convert to template
    xmss_set_params(&params, 32, h, 16);

    unsigned int n = params.n;
    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;

    //Construct SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte) from n-byte seed
    unsigned char randombits[3 * n];
    shake256(randombits, 3 * n, seed, n);

    // Copy PUB_SEED to public key
    memcpy(sk + 4, randombits, 3 * n);
    memcpy(pk + n, sk + 4 + 2 * n, n);

    uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    // Compute root
    treehash(pk, params.h, 0, sk + 4, &params, sk + 4 + 2 * n, addr);
    // copy root to sk
    memcpy(sk + 4 + 3 * n, pk, n);

    return 0;
}

int xmss_updateSK(unsigned char *sk, unsigned long k) {
    //unsigned long idxkey=0;
    //idxkey = ((unsigned long)sig_msg[0] << 24) | ((unsigned long)sig_msg[1] << 16) | ((unsigned long)sig_msg[2] << 8) | sig_msg[3];
    uint32_t idxkey =
            ((unsigned long) sk[0] << 24) | ((unsigned long) sk[1] << 16) | ((unsigned long) sk[2] << 8) | sk[3];
    if (idxkey >= k) {
        return -1;
        //the secret key is updated more than the blockchain, so all fine
    } else {
        uint32_t idx = k;
        //update secret key index
        sk[0] = ((idx) >> 24) & 255;
        sk[1] = ((idx) >> 16) & 255;
        sk[2] = ((idx) >> 8) & 255;
        sk[3] = (idx) & 255;
        return 0;
    }
}

int xmss_Signmsg(unsigned char *sk, unsigned char *sig_msg, unsigned char *msg, unsigned int h) {
    unsigned long long sig_msg_len;
    unsigned long long msglen = 32;
    xmss_set_params(&params, 32, h, 16);
    uint16_t n = params.n;
    uint16_t i = 0;

    // Extract SK
    uint32_t idx = ((unsigned long) sk[0] << 24) | ((unsigned long) sk[1] << 16) | ((unsigned long) sk[2] << 8) | sk[3];
    unsigned char sk_seed[n];
    memcpy(sk_seed, sk + 4, n);
    unsigned char sk_prf[n];
    memcpy(sk_prf, sk + 4 + n, n);
    unsigned char pub_seed[n];
    memcpy(pub_seed, sk + 4 + 2 * n, n);

    // index as 32 bytes string
    unsigned char idx_bytes_32[32];
    to_byte(idx_bytes_32, idx, 32);


    unsigned char hash_key[3 * n];

    // Update SK
    sk[0] = ((idx + 1) >> 24) & 255;
    sk[1] = ((idx + 1) >> 16) & 255;
    sk[2] = ((idx + 1) >> 8) & 255;
    sk[3] = (idx + 1) & 255;
    // -- Secret key for this non-forward-secure version is now updated.
    // -- A productive implementation should use a file handle instead and write the updated secret key at this point!

    // Init working params
    unsigned char R[n];
    unsigned char msg_h[n];
    unsigned char root[n];
    unsigned char ots_seed[n];
    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    prf(R, idx_bytes_32, sk_prf, n);
    // Generate hash key (R || root || idx)
    memcpy(hash_key, R, n);
    memcpy(hash_key + n, sk + 4 + 3 * n, n);
    to_byte(hash_key + 2 * n, idx, n);
    // Then use it for message digest
    h_msg(msg_h, msg, msglen, hash_key, 3 * n, n);

    // Start collecting signature
    sig_msg_len = 0;

    // Copy index to signature
    sig_msg[0] = (idx >> 24) & 255;
    sig_msg[1] = (idx >> 16) & 255;
    sig_msg[2] = (idx >> 8) & 255;
    sig_msg[3] = idx & 255;

    sig_msg += 4;
    sig_msg_len += 4;

    // Copy R to signature
    for (i = 0; i < n; i++)
        sig_msg[i] = R[i];
    sig_msg += n;
    sig_msg_len += n;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Prepare Address
    setType(ots_addr, 0);
    setOTSADRS(ots_addr, idx);

    // Compute seed for OTS key pair
    get_seed(ots_seed, sk_seed, n, ots_addr);

    // Compute WOTS signature
    wots_sign(sig_msg, msg_h, ots_seed, &(params.wots_par), pub_seed, ots_addr);

    sig_msg += params.wots_par.keysize;
    sig_msg_len += params.wots_par.keysize;

    compute_authpath_wots(root, sig_msg, idx, sk_seed, &params, pub_seed, ots_addr);
    sig_msg += params.h * n;
    sig_msg_len += params.h * n;

    //Whipe secret elements?
    //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

    //  memcpy(sig_msg, msg, msglen);
    //sig_msg_len += msglen;
    return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmss_Verifysig(unsigned char *msg,
                   unsigned char *sig_msg,
                   const unsigned char *pk,
                   unsigned char h) {

    xmss_set_params(&params, 32, h, 16);
    unsigned long long msglen = 32;
    unsigned long long sig_msg_len = static_cast<unsigned long long int>(4 + 32 + 67 * 32 + h * 32);
    uint16_t n = params.n;

    unsigned long long i, m_len;
    unsigned long idx = 0;
    unsigned char wots_pk[params.wots_par.keysize];
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
    unsigned long long tmp_sig_len = params.wots_par.keysize + params.h * n;
    m_len = sig_msg_len - tmp_sig_len;
    //h_msg(msg_h, sig_msg + tmp_sig_len, m_len, hash_key, 3*n, n);
    h_msg(msg_h, msg, msglen, hash_key, 3 * n, n);
    //-----------------------
    // Verify signature
    //-----------------------

    // Prepare Address
    setOTSADRS(ots_addr, idx);
    // Check WOTS signature
    wots_pkFromSig(wots_pk, sig_msg, msg_h, &(params.wots_par), pub_seed, ots_addr);

    sig_msg += params.wots_par.keysize;
    sig_msg_len -= params.wots_par.keysize;

    // Compute Ltree
    setLtreeADRS(ltree_addr, idx);
    l_tree(pkhash, wots_pk, &params, pub_seed, ltree_addr);

    // Compute root
    validate_authpath(root, pkhash, idx, sig_msg, &params, pub_seed, node_addr);

    sig_msg += params.h * n;
    sig_msg_len -= params.h * n;

    for (i = 0; i < n; i++)
        if (root[i] != pk[i])
            goto fail;

    msglen = sig_msg_len;
    for (i = 0; i < msglen; i++)
        msg[i] = sig_msg[i];

    return 0;

    fail:
    msglen = sig_msg_len;
    for (i = 0; i < msglen; i++)
        msg[i] = 0;
    msglen = -1;
    return -1;
}
