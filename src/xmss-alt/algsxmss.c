// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld

#include "algsxmss.h"
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <crypto/secure_memory.h>

#include "hash.h"
#include "hash_address.h"
#include "fips202.h"

namespace {
constexpr size_t SUPPORTED_XMSS_N = 32;
constexpr size_t SUPPORTED_XMSS_MAX_HEIGHT = 30;
constexpr size_t SUPPORTED_XMSS_MAX_WOTS_KEYSIZE = 265 * SUPPORTED_XMSS_N;
}

/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes n byte sk_seed and returns n byte seed using 32 byte address addr.
 */
void get_seed(eHashFunction hash_func,
              unsigned char *seed,
              const unsigned char *sk_seed,
              int n, uint32_t addr[8]) {
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
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */

void gen_leaf_wots(eHashFunction hash_func,
                          unsigned char *leaf,
                          const unsigned char *sk_seed,
                          const xmss_params *params,
                          const unsigned char *pub_seed,
                          uint32_t ltree_addr[8],
                          uint32_t ots_addr[8]) {
    if (!xmss_hash_function_is_valid(hash_func) ||
        !xmss_params_are_valid(params) || leaf == nullptr ||
        sk_seed == nullptr || pub_seed == nullptr || ltree_addr == nullptr ||
        ots_addr == nullptr) {
        return;
    }
    unsigned char seed[SUPPORTED_XMSS_N];
    qrllib::secure_memory::RangeWipeGuard seed_guard(seed, sizeof(seed));
    unsigned char pk[SUPPORTED_XMSS_MAX_WOTS_KEYSIZE];
    qrllib::secure_memory::RangeWipeGuard pk_guard(
            pk, params->wots_par.keysize);

    get_seed(hash_func, seed, sk_seed, params->n, ots_addr);
    wots_pkgen(hash_func, pk, seed, &(params->wots_par), pub_seed, ots_addr);

    l_tree(hash_func, &params->wots_par, leaf, pk, pub_seed, ltree_addr);
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */

static void
treehash(eHashFunction hash_func,
         unsigned char *node,
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
    unsigned char stack[(SUPPORTED_XMSS_MAX_HEIGHT + 1) * SUPPORTED_XMSS_N];
    uint16_t stacklevels[SUPPORTED_XMSS_MAX_HEIGHT + 1];
    unsigned int stackoffset = 0;

    lastnode = idx + (1U << height);

    for (; idx < lastnode; idx++) {
        setLtreeADRS(ltree_addr, idx);
        setOTSADRS(ots_addr, idx);
        gen_leaf_wots(hash_func, stack + stackoffset * n, sk_seed, params, pub_seed, ltree_addr, ots_addr);
        stacklevels[stackoffset] = 0;
        stackoffset++;
        while (stackoffset > 1 && stacklevels[stackoffset - 1] == stacklevels[stackoffset - 2]) {
            setTreeHeight(node_addr, stacklevels[stackoffset - 1]);
            setTreeIndex(node_addr, (idx >> (stacklevels[stackoffset - 1] + 1)));
            hash_h(hash_func, stack + (stackoffset - 2) * n, stack + (stackoffset - 2) * n, pub_seed,
                   node_addr, n);
            stacklevels[stackoffset - 2]++;
            stackoffset--;
        }
    }
    for (i = 0; i < n; i++)
        node[i] = stack[i];
}

/**
 * Computes the authpath and the root. This method is using a lot of space as we build the whole tree and then select the authpath nodes.
 * For more efficient algorithms see e.g. the chapter on hash-based signatures in Bernstein, Buchmann, Dahmen. "Post-quantum Cryptography", Springer 2009.
 * It returns the authpath in "authpath" with the node on level 0 at index 0.
 */
static int compute_authpath_wots(eHashFunction hash_func,
                                 unsigned char *root,
                                 unsigned char *authpath,
                                 unsigned long leaf_idx,
                                 const unsigned char *sk_seed,
                                 const xmss_params *params,
                                 unsigned char *pub_seed,
                                 uint32_t addr[8]) {
    uint32_t i, j, level;
    uint32_t n = params->n;
    uint32_t h = params->h;

    const size_t leaf_count = size_t{1} << h;
    if (n == 0 || leaf_count > std::numeric_limits<size_t>::max() / (2U * n)) {
        return -1;
    }
    const size_t tree_size = 2U * leaf_count * n;
    // SHA2 hashing can throw while building the tree; retain ownership on unwind.
    std::unique_ptr<unsigned char, decltype(&free)> tree_owner(
            static_cast<unsigned char *>(malloc(tree_size)), &free);
    unsigned char *tree = tree_owner.get();
    if (tree == NULL) {
        return -1;
    }

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
        const size_t leaf_offset = leaf_count * n + static_cast<size_t>(i) * n;
        gen_leaf_wots(hash_func, tree + leaf_offset, sk_seed, params,
                      pub_seed, ltree_addr, ots_addr);
    }


    level = 0;
    // Compute tree:
    // Outer loop: For each inner layer
    for (i = (1U << h); i > 1; i >>= 1) {
        setTreeHeight(node_addr, level);
        // Inner loop: for each pair of sibling nodes
        for (j = 0; j < i; j += 2) {
            setTreeIndex(node_addr, j >> 1);
            const size_t output_offset =
                (static_cast<size_t>(i) >> 1) * n +
                (static_cast<size_t>(j) >> 1) * n;
            const size_t input_offset =
                static_cast<size_t>(i) * n + static_cast<size_t>(j) * n;
            hash_h(hash_func, tree + output_offset, tree + input_offset,
                   pub_seed, node_addr, n);
        }
        level++;
    }

    // copy authpath
    for (i = 0; i < h; i++)
        memcpy(authpath + static_cast<size_t>(i) * n,
               tree + (leaf_count >> i) * n +
                   static_cast<size_t>((leaf_idx >> i) ^ 1UL) * n,
               n);

    // copy root
    memcpy(root, tree + n, n);

    return 0;
}


int xmss_Genkeypair(eHashFunction hash_func,
                    xmss_params *params,
                    unsigned char *pk,
                    unsigned char *sk,
                    unsigned char *seed) {
    if (!xmss_hash_function_is_valid(hash_func) ||
        !xmss_params_are_valid(params) ||
        pk == nullptr || sk == nullptr || seed == nullptr) {
        return -1;
    }
    unsigned int n = params->n;
    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;

    //Construct SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte) from n-byte seed
    unsigned char randombits[3 * SUPPORTED_XMSS_N];
    qrllib::secure_memory::RangeWipeGuard randombits_guard(randombits, sizeof(randombits));
    shake256(randombits, 3 * n, seed, 48);

    // Copy PUB_SEED to public key
    memcpy(sk + 4, randombits, 3 * n);
    memcpy(pk + n, sk + 4 + 2 * n, n);

    uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    // Compute root
    treehash(hash_func, pk, params->h, 0, sk + 4, params, sk + 4 + 2 * n, addr);
    // copy root to sk
    memcpy(sk + 4 + 3 * n, pk, n);

    return 0;
}

int xmss_updateSK(unsigned char *sk, unsigned long k) {
    if (sk == nullptr || k > UINT32_MAX) {
        return -1;
    }
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

int xmss_Signmsg(eHashFunction hash_func,
                 xmss_params *params,
                 unsigned char *sk,
                 unsigned char *sig_msg,
                 const unsigned char *msg,
                 size_t msglen) {
    if (!xmss_hash_function_is_valid(hash_func) ||
        !xmss_params_are_valid(params) ||
        sk == nullptr || sig_msg == nullptr ||
        (msg == nullptr && msglen != 0)) {
        return -1;
    }
    unsigned long long sig_msg_len;
    uint16_t n = params->n;
    uint16_t i = 0;

    // Extract SK
    uint32_t idx = ((unsigned long) sk[0] << 24) | ((unsigned long) sk[1] << 16) | ((unsigned long) sk[2] << 8) | sk[3];
    if (idx >= (uint32_t{1} << params->h)) {
        return -1;
    }
    unsigned char sk_seed[SUPPORTED_XMSS_N];
    qrllib::secure_memory::RangeWipeGuard sk_seed_guard(sk_seed, sizeof(sk_seed));
    memcpy(sk_seed, sk + 4, n);
    unsigned char sk_prf[SUPPORTED_XMSS_N];
    qrllib::secure_memory::RangeWipeGuard sk_prf_guard(sk_prf, sizeof(sk_prf));
    memcpy(sk_prf, sk + 4 + n, n);
    unsigned char pub_seed[SUPPORTED_XMSS_N];
    memcpy(pub_seed, sk + 4 + 2 * n, n);

    // index as 32 bytes string
    unsigned char idx_bytes_32[32];
    to_byte(idx_bytes_32, idx, 32);


    unsigned char hash_key[3 * SUPPORTED_XMSS_N];
    qrllib::secure_memory::RangeWipeGuard hash_key_guard(hash_key, sizeof(hash_key));

    // Update SK
    sk[0] = ((idx + 1) >> 24) & 255;
    sk[1] = ((idx + 1) >> 16) & 255;
    sk[2] = ((idx + 1) >> 8) & 255;
    sk[3] = (idx + 1) & 255;
    // -- Secret key for this non-forward-secure version is now updated.
    // -- A productive implementation should use a file handle instead and write the updated secret key at this point!

    // Init working params
    unsigned char R[SUPPORTED_XMSS_N];
    unsigned char msg_h[SUPPORTED_XMSS_N];
    unsigned char root[SUPPORTED_XMSS_N];
    unsigned char ots_seed[SUPPORTED_XMSS_N];
    qrllib::secure_memory::RangeWipeGuard ots_seed_guard(ots_seed, sizeof(ots_seed));
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
    if (h_msg(hash_func, msg_h, msg, msglen, hash_key, 3 * n, n) != 0) {
        return -1;
    }

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

    if (compute_authpath_wots(hash_func, root, sig_msg, idx, sk_seed, params, pub_seed, ots_addr) != 0) {
        return -1;
    }
    sig_msg += params->h * n;
    sig_msg_len += params->h * n;

    //Whipe secret elements?
    //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

    //  memcpy(sig_msg, msg, msglen);
    //sig_msg_len += msglen;
    return 0;
}
