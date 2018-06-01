// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
xmss_fast.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "algsxmss_fast.h"
#include <cstring>
#include "fips202.h"
#include "hash.h"
#include "hash_address.h"
#include <cstdio>
#include <stdexcept>

/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes n byte sk_seed and returns n byte seed using 32 byte address addr.
 */
static void get_seed(eHashFunction hash_func,
                     unsigned char *seed,
                     const unsigned char *sk_seed,
                     int n,
                     uint32_t addr[8])
{
    unsigned char bytes[32];

    // Make sure that chain addr, hash addr, and key bit are 0!
    setChainADRS(addr, 0);
    setHashADRS(addr, 0);
    setKeyAndMask(addr, 0);

    // Generate pseudorandom value
    addr_to_byte(bytes, addr);
    prf(hash_func, seed, bytes, sk_seed, n);
}

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
                        unsigned int next_leaf)
{
    state->stack = stack;
    state->stackoffset = stackoffset;
    state->stacklevels = stacklevels;
    state->auth = auth;
    state->keep = keep;
    state->treehash = treehash;
    state->retain = retain;
    state->next_leaf = next_leaf;
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */
static void gen_leaf_wots(eHashFunction hash_func,
                          unsigned char *leaf,
                          const unsigned char *sk_seed,
                          const xmss_params *params,
                          const unsigned char *pub_seed,
                          uint32_t ltree_addr[8],
                          uint32_t ots_addr[8])
{
    unsigned char seed[params->n];
    unsigned char pk[params->wots_par.keysize];

    get_seed(hash_func, seed, sk_seed, params->n, ots_addr);
    wots_pkgen(hash_func, pk, seed, &(params->wots_par), pub_seed, ots_addr);

    l_tree(hash_func, &params->wots_par, leaf, pk, pub_seed, ltree_addr);
}

static int treehash_minheight_on_stack(bds_state *state, const xmss_params *params, const treehash_inst *treehash)
{
    unsigned int r = params->h, i;
    for (i = 0; i < treehash->stackusage; i++) {
        if (state->stacklevels[state->stackoffset - i - 1] < r) {
            r = state->stacklevels[state->stackoffset - i - 1];
        }
    }
    return r;
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */
static void treehash_setup(eHashFunction hash_func,
                           unsigned char *node,
                           int height,
                           int index,
                           bds_state *state,
                           const unsigned char *sk_seed,
                           const xmss_params *params,
                           const unsigned char *pub_seed,
                           const uint32_t addr[8])
{
    unsigned int idx = index;
    unsigned int n = params->n;
    unsigned int h = params->h;
    unsigned int k = params->k;
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
    unsigned int stacklevels[height + 1];
    unsigned int stackoffset = 0;
    unsigned int nodeh;

    lastnode = idx + (1 << height);

    const int bound = h - k;
    for (i = 0; i < bound; i++) {
        state->treehash[i].h = i;
        state->treehash[i].completed = 1;
        state->treehash[i].stackusage = 0;
    }

    i = 0;
    for (; idx < lastnode; idx++) {
        setLtreeADRS(ltree_addr, idx);
        setOTSADRS(ots_addr, idx);
        gen_leaf_wots(hash_func, stack + stackoffset * n, sk_seed, params, pub_seed, ltree_addr, ots_addr);
        stacklevels[stackoffset] = 0;
        stackoffset++;
        if (h - k > 0 && i == 3) {
            memcpy(state->treehash[0].node, stack + stackoffset * n, n);
        }
        while (stackoffset > 1 && stacklevels[stackoffset - 1] == stacklevels[stackoffset - 2]) {
            nodeh = stacklevels[stackoffset - 1];
            if (i >> nodeh == 1) {
                memcpy(state->auth + nodeh * n, stack + (stackoffset - 1) * n, n);
            }
            else {
                if (nodeh < h - k && i >> nodeh == 3) {
                    memcpy(state->treehash[nodeh].node, stack + (stackoffset - 1) * n, n);
                }
                else if (nodeh >= h - k) {
                    memcpy(state->retain + ((1 << (h - 1 - nodeh)) + nodeh - h + (((i >> nodeh) - 3) >> 1)) * n,
                           stack + (stackoffset - 1) * n, n);
                }
            }
            setTreeHeight(node_addr, stacklevels[stackoffset - 1]);
            setTreeIndex(node_addr, (idx >> (stacklevels[stackoffset - 1] + 1)));
            hash_h(hash_func, stack + (stackoffset - 2) * n, stack + (stackoffset - 2) * n, pub_seed,
                   node_addr, n);
            stacklevels[stackoffset - 2]++;
            stackoffset--;
        }
        i++;
    }

    for (i = 0; i < n; i++)
        node[i] = stack[i];
}

static void
treehash_update(eHashFunction hash_func,
                treehash_inst *treehash, bds_state *state, const unsigned char *sk_seed, const xmss_params *params,
                const unsigned char *pub_seed, const uint32_t addr[8])
{
    int n = params->n;

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

    setLtreeADRS(ltree_addr, treehash->next_idx);
    setOTSADRS(ots_addr, treehash->next_idx);

    unsigned char nodebuffer[2 * n];
    unsigned int nodeheight = 0;
    gen_leaf_wots(hash_func, nodebuffer, sk_seed, params, pub_seed, ltree_addr, ots_addr);
    while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset - 1] == nodeheight) {
        memcpy(nodebuffer + n, nodebuffer, n);
        memcpy(nodebuffer, state->stack + (state->stackoffset - 1) * n, n);
        setTreeHeight(node_addr, nodeheight);
        setTreeIndex(node_addr, (treehash->next_idx >> (nodeheight + 1)));
        hash_h(hash_func, nodebuffer, nodebuffer, pub_seed, node_addr, n);
        nodeheight++;
        treehash->stackusage--;
        state->stackoffset--;
    }
    if (nodeheight == treehash->h) { // this also implies stackusage == 0
        memcpy(treehash->node, nodebuffer, n);
        treehash->completed = 1;
    }
    else {
        memcpy(state->stack + state->stackoffset * n, nodebuffer, n);
        treehash->stackusage++;
        state->stacklevels[state->stackoffset] = nodeheight;
        state->stackoffset++;
        treehash->next_idx++;
    }
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void
validate_authpath(eHashFunction hash_func,
                  unsigned char *root, const unsigned char *leaf, unsigned long leafidx, const unsigned char *authpath,
                  const xmss_params *params, const unsigned char *pub_seed, uint32_t addr[8])
{
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
    }
    else {
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
            hash_h(hash_func, buffer + n, buffer, pub_seed, addr, n);
            for (j = 0; j < n; j++)
                buffer[j] = authpath[j];
        }
        else {
            hash_h(hash_func, buffer, buffer, pub_seed, addr, n);
            for (j = 0; j < n; j++)
                buffer[j + n] = authpath[j];
        }
        authpath += n;
    }
    setTreeHeight(addr, (params->h - 1));
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    hash_h(hash_func, root, buffer, pub_seed, addr, n);
}

/**
 * Performs one treehash update on the instance that needs it the most.
 * Returns 1 if such an instance was not found
 **/
static char
bds_treehash_update(eHashFunction hash_func,
                    bds_state *state, unsigned int updates, const unsigned char *sk_seed, const xmss_params *params,
                    unsigned char *pub_seed, const uint32_t addr[8])
{
    uint32_t i, j;
    unsigned int level, l_min, low;
    unsigned int h = params->h;
    unsigned int k = params->k;
    unsigned int used = 0;

    for (j = 0; j < updates; j++) {
        l_min = h;
        level = h - k;
        for (i = 0; i < h - k; i++) {
            if (state->treehash[i].completed) {
                low = h;
            }
            else if (state->treehash[i].stackusage == 0) {
                low = i;
            }
            else {
                low = treehash_minheight_on_stack(state, params, &(state->treehash[i]));
            }
            if (low < l_min) {
                level = i;
                l_min = low;
            }
        }
        if (level == h - k) {
            break;
        }
        treehash_update(hash_func, &(state->treehash[level]), state, sk_seed, params, pub_seed, addr);
        used++;
    }
    return updates - used;
}

/**
 * Updates the state (typically NEXT_i) by adding a leaf and updating the stack
 * Returns 1 if all leaf nodes have already been processed
 **/
static char bds_state_update(eHashFunction hash_func,
                             bds_state *state,
                             const unsigned char *sk_seed,
                             const xmss_params *params,
                             const unsigned char *pub_seed,
                             const uint32_t addr[8])
{
    uint32_t XMSS_N = params->n;
    uint32_t XMSS_TREEHEIGHT = params->h;
    uint32_t XMSS_BDS_K = params->k;

    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
    uint32_t ots_addr[8];

    int nodeh;
    int idx = state->next_leaf;
    if (idx == 1 << XMSS_TREEHEIGHT) {
        return 1;
    }

    // only copy layer and tree address parts
    memcpy(ots_addr, addr, 12);
    // type = ots
    setType(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    setType(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    setType(node_addr, 2);

    setOTSADRS(ots_addr, idx);
    setLtreeADRS(ltree_addr, idx);

    gen_leaf_wots(
        hash_func,
        state->stack + state->stackoffset * XMSS_N,
        sk_seed,
        params,
        pub_seed,
        ltree_addr,
        ots_addr);

    state->stacklevels[state->stackoffset] = 0;
    state->stackoffset++;
    if (XMSS_TREEHEIGHT - XMSS_BDS_K > 0 && idx == 3) {
        memcpy(state->treehash[0].node, state->stack + state->stackoffset * XMSS_N, XMSS_N);
    }
    while (state->stackoffset > 1
        && state->stacklevels[state->stackoffset - 1] == state->stacklevels[state->stackoffset - 2]) {
        nodeh = state->stacklevels[state->stackoffset - 1];
        if (idx >> nodeh == 1) {
            memcpy(state->auth + nodeh * XMSS_N, state->stack + (state->stackoffset - 1) * XMSS_N, XMSS_N);
        }
        else {
            if (nodeh < XMSS_TREEHEIGHT - XMSS_BDS_K && idx >> nodeh == 3) {
                memcpy(state->treehash[nodeh].node, state->stack + (state->stackoffset - 1) * XMSS_N, XMSS_N);
            }
            else if (nodeh >= XMSS_TREEHEIGHT - XMSS_BDS_K) {
                memcpy(state->retain + ((1 << (XMSS_TREEHEIGHT - 1 - nodeh)) + nodeh - XMSS_TREEHEIGHT
                    + (((idx >> nodeh) - 3) >> 1)) * XMSS_N, state->stack + (state->stackoffset - 1) * XMSS_N, XMSS_N);
            }
        }

        setTreeHeight(node_addr, state->stacklevels[state->stackoffset - 1]);
        setTreeIndex(node_addr, (idx >> (state->stacklevels[state->stackoffset - 1] + 1)));

        hash_h(hash_func,
               state->stack + (state->stackoffset - 2) * XMSS_N,
               state->stack + (state->stackoffset - 2) * XMSS_N,
               pub_seed,
               node_addr,
               XMSS_N);

        state->stacklevels[state->stackoffset - 2]++;
        state->stackoffset--;
    }
    state->next_leaf++;
    return 0;
}
/**
 * Returns the auth path for node leaf_idx and computes the auth path for the
 * next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
 * in "Post Quantum Cryptography", Springer 2009.
 */
static void
bds_round(eHashFunction hash_func,
          bds_state *state,
          const unsigned long leaf_idx,
          const unsigned char *sk_seed,
          const xmss_params *params,
          unsigned char *pub_seed,
          uint32_t addr[8])
{
    unsigned int i;
    unsigned int n = params->n;
    unsigned int h = params->h;
    unsigned int k = params->k;

    unsigned int tau = h;
    unsigned int startidx;
    unsigned int offset, rowidx;
    unsigned char buf[2 * n];

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

    for (i = 0; i < h; i++) {
        if (!((leaf_idx >> i) & 1)) {
            tau = i;
            break;
        }
    }

    if (tau > 0) {
        memcpy(buf, state->auth + (tau - 1) * n, n);
        // we need to do this before refreshing state->keep to prevent overwriting
        memcpy(buf + n, state->keep + ((tau - 1) >> 1) * n, n);
    }
    if (!((leaf_idx >> (tau + 1)) & 1) && (tau < h - 1)) {
        memcpy(state->keep + (tau >> 1) * n, state->auth + tau * n, n);
    }
    if (tau == 0) {
        setLtreeADRS(ltree_addr, leaf_idx);
        setOTSADRS(ots_addr, leaf_idx);
        gen_leaf_wots(hash_func, state->auth, sk_seed, params, pub_seed, ltree_addr, ots_addr);
    }
    else {
        setTreeHeight(node_addr, (tau - 1));
        setTreeIndex(node_addr, leaf_idx >> tau);
        hash_h(hash_func, state->auth + tau * n, buf, pub_seed, node_addr, n);
        for (i = 0; i < tau; i++) {
            if (i < h - k) {
                memcpy(state->auth + i * n, state->treehash[i].node, n);
            }
            else {
                offset = (1 << (h - 1 - i)) + i - h;
                rowidx = ((leaf_idx >> i) - 1) >> 1;
                memcpy(state->auth + i * n, state->retain + (offset + rowidx) * n, n);
            }
        }

        for (i = 0; i < ((tau < h - k) ? tau : (h - k)); i++) {
            startidx = leaf_idx + 1 + 3 * (1 << i);
            if (startidx < 1U << h) {
                state->treehash[i].h = i;
                state->treehash[i].next_idx = startidx;
                state->treehash[i].completed = 0;
                state->treehash[i].stackusage = 0;
            }
        }
    }
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssfast_Genkeypair(eHashFunction hash_func,
                        xmss_params *params,            // TODO: Refactor this. Remove params, etc.
                        unsigned char *pk,
                        unsigned char *sk,
                        bds_state *state,
                        unsigned char *seed)
{
    if (params->h & 1) {
        printf("Not a valid h, only even numbers supported! Try again with an even number");
        return -1;
    }
    unsigned int k = params->k;
    unsigned int n = params->n;

    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;

    // Copy PUB_SEED to public key
    unsigned char randombits[3 * n];
    shake256(randombits, 3 * n, seed, 48);  // FIXME: seed size has been hardcoded to 48
    size_t rnd = 96;
    size_t pks = 32;
    memcpy(sk + 4, randombits, rnd);
    memcpy(pk + n, sk + 4 + 2 * n, pks);

    uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    // Compute root
    treehash_setup(hash_func, pk, params->h, 0, state, sk + 4, params, sk + 4 + 2 * n, addr);
    // copy root to sk
    memcpy(sk + 4 + 3 * n, pk, pks);
    return 0;
}

int xmssfast_update(eHashFunction hash_func,
                    xmss_params *params,
                    unsigned char *sk,
                    bds_state *state,
                    uint32_t new_idx)
{
    const uint32_t num_elems = (1U << params->h);

    auto current_idx = static_cast<uint32_t>(
        ((unsigned long) sk[0] << 24) |
        ((unsigned long) sk[1] << 16) |
        ((unsigned long) sk[2] << 8) |
        sk[3]);

    // Verify ranges
    if (new_idx>=num_elems)
    {
        throw std::invalid_argument("index too high");
    }

    if (new_idx<current_idx)
    {
        throw std::invalid_argument("cannot rewind");
    }

    // Change index
    unsigned char sk_seed[32];
    memcpy(sk_seed, sk + 4, 32);

    unsigned char pub_seed[32];
    memcpy(pub_seed, sk + 4 + 2 * 32, 32);

    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    for (unsigned int j = current_idx; j < new_idx; j++) {
        if (j >= num_elems)
        {
            return -1;
        }

        bds_round(hash_func, state, j, sk_seed, params, pub_seed, ots_addr);
        bds_treehash_update(hash_func,
                            state,
                            (params->h - params->k) >> 1,
                            sk_seed,
                            params,
                            pub_seed,
                            ots_addr);
    }

    //update secret key index
    sk[0] = static_cast<unsigned char>(((new_idx) >> 24) & 255);
    sk[1] = static_cast<unsigned char>(((new_idx) >> 16) & 255);
    sk[2] = static_cast<unsigned char>(((new_idx) >> 8) & 255);
    sk[3] = static_cast<unsigned char>((new_idx) & 255);

    return 0;
}

int xmssfast_Signmsg(eHashFunction hash_func,
                     xmss_params *params,
                     unsigned char *sk,
                     bds_state *state,
                     unsigned char *sig_msg,
                     unsigned char *msg,
                     unsigned long long msglen)
{
    unsigned int n = params->n;
    uint16_t i = 0;

    // Extract SK
    unsigned long idx =
        ((unsigned long) sk[0] << 24) | ((unsigned long) sk[1] << 16) | ((unsigned long) sk[2] << 8) | sk[3];
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
    unsigned long long sig_msg_len;
    // Init working params
    unsigned char R[n];
    unsigned char msg_h[n];
    unsigned char ots_seed[n];
    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    prf(hash_func, R, idx_bytes_32, sk_prf, n);
    // Generate hash key (R || root || idx)
    memcpy(hash_key, R, n);
    memcpy(hash_key + n, sk + 4 + 3 * n, n);
    to_byte(hash_key + 2 * n, idx, n);
    // Then use it for message digest
    h_msg(hash_func, msg_h, msg, msglen, hash_key, 3 * n, n);

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
    get_seed(hash_func, ots_seed, sk_seed, n, ots_addr);

    // Compute WOTS signature
    wots_sign(hash_func, sig_msg, msg_h, ots_seed, &(params->wots_par), pub_seed, ots_addr);
    sig_msg += params->wots_par.keysize;
    sig_msg_len += params->wots_par.keysize;

    // the auth path was already computed during the previous round
    memcpy(sig_msg, state->auth, params->h * params->n);

    if (idx < (1U << params->h) - 1) {
        bds_round(hash_func, state, idx, sk_seed, params, pub_seed, ots_addr);
        bds_treehash_update(hash_func, state, (params->h - params->k) >> 1, sk_seed, params, pub_seed, ots_addr);
    }

    sig_msg += params->h * params->n;
    sig_msg_len += params->h * params->n;

    //Whipe secret elements?
    //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

    //  memcpy(sig_msg, msg, msglen);
    //*sig_msg_len += msglen;
    //printf("%d",sig_msg_len);
    return 0;
}
