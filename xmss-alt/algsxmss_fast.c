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
#include <cstdlib>
#include <cstring>
#include <cmath>
#include "fips202.h"
#include "hash.h"
#include "xmss_commons.h"
#include "hash_address.h"
#include <cstdio>

xmssfast_params paramsfast;

/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes n byte sk_seed and returns n byte seed using 32 byte address addr.
 */
static void get_seed(unsigned char *seed, const unsigned char *sk_seed, int n, uint32_t addr[8])
{
  unsigned char bytes[32];
  // Make sure that chain addr, hash addr, and key bit are 0!
  setChainADRS(addr,0);
  setHashADRS(addr,0);
  setKeyAndMask(addr,0);
  // Generate pseudorandom value
  addr_to_byte(bytes, addr);
  prf(seed, bytes, sk_seed, n);
}

/**
 * Initialize xmss params struct
 * parameter names are the same as in the draft
 * parameter k is K as used in the BDS algorithm
 */
int xmssfast_set_params(xmssfast_params *params, int n, int h, int w, int k)
{
  if (k >= h || k < 2 || (h - k) % 2) {
    fprintf(stderr, "For BDS traversal, H - K must be even, with H > K >= 2!\n");
    return 1;
  }
  params->h = h;
  params->n = n;
  params->k = k;
  wots_params wots_par;
  wots_set_params(&wots_par, n, w);
  params->wots_par = wots_par;
  return 0;
}

/**
 * Initialize BDS state struct
 * parameter names are the same as used in the description of the BDS traversal
 */
void xmss_set_bds_state(bds_state *state, unsigned char *stack, unsigned int stackoffset, unsigned char *stacklevels, unsigned char *auth, unsigned char *keep, treehash_inst *treehash, unsigned char *retain, unsigned int next_leaf)
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
 * Computes a leaf from a WOTS public key using an L-tree.
 */
static void l_tree(unsigned char *leaf, unsigned char *wots_pk, const xmssfast_params *params, const unsigned char *pub_seed, uint32_t addr[8])
{
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
       hash_h(wots_pk+i*n, wots_pk+i*2*n, pub_seed, addr, n);
     }
     //if ( l % 2 == 1 ) {
     if (l & 1) {
       //pk[floor(l / 2) + 1] = pk[l];
       memcpy(wots_pk+(l>>1)*n, wots_pk+(l-1)*n, n);
       //l = ceil(l / 2);
       l=(l>>1)+1;
     }
     else {
       //l = ceil(l / 2);
       l=(l>>1);
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
static void gen_leaf_wots(unsigned char *leaf, const unsigned char *sk_seed, const xmssfast_params *params, const unsigned char *pub_seed, uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
  unsigned char seed[params->n];
  unsigned char pk[params->wots_par.keysize];

  get_seed(seed, sk_seed, params->n, ots_addr);
  wots_pkgen(pk, seed, &(params->wots_par), pub_seed, ots_addr);

  l_tree(leaf, pk, params, pub_seed, ltree_addr);
}

static int treehash_minheight_on_stack(bds_state* state, const xmssfast_params *params, const treehash_inst *treehash) {
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
static void treehash_setup(unsigned char *node, int height, int index, bds_state *state, const unsigned char *sk_seed, const xmssfast_params *params, const unsigned char *pub_seed, const uint32_t addr[8])
{
  unsigned int idx = index;
  unsigned int n = params->n;
  unsigned int h = params->h;
  unsigned int k = params->k;
  // use three different addresses because at this point we use all three formats in parallel
  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t  node_addr[8];
  // only copy layer and tree address parts
  memcpy(ots_addr, addr, 12);
  // type = ots
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);

  uint32_t lastnode, i;
  unsigned char stack[(height+1)*n];
  unsigned int stacklevels[height+1];
  unsigned int stackoffset=0;
  unsigned int nodeh;

  lastnode = idx+(1<<height);

  for (i = 0; i < h-k; i++) {
    state->treehash[i].h = i;
    state->treehash[i].completed = 1;
    state->treehash[i].stackusage = 0;
  }

  i = 0;
  for (; idx < lastnode; idx++) {
    setLtreeADRS(ltree_addr, idx);
    setOTSADRS(ots_addr, idx);
    gen_leaf_wots(stack+stackoffset*n, sk_seed, params, pub_seed, ltree_addr, ots_addr);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    if (h - k > 0 && i == 3) {
      memcpy(state->treehash[0].node, stack+stackoffset*n, n);
    }
    while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2])
    {
      nodeh = stacklevels[stackoffset-1];
      if (i >> nodeh == 1) {
        memcpy(state->auth + nodeh*n, stack+(stackoffset-1)*n, n);
      }
      else {
        if (nodeh < h - k && i >> nodeh == 3) {
          memcpy(state->treehash[nodeh].node, stack+(stackoffset-1)*n, n);
        }
        else if (nodeh >= h - k) {
          memcpy(state->retain + ((1 << (h - 1 - nodeh)) + nodeh - h + (((i >> nodeh) - 3) >> 1)) * n, stack+(stackoffset-1)*n, n);
        }
      }
      setTreeHeight(node_addr, stacklevels[stackoffset-1]);
      setTreeIndex(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
      hash_h(stack+(stackoffset-2)*n, stack+(stackoffset-2)*n, pub_seed,
          node_addr, n);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
    i++;
  }

  for (i = 0; i < n; i++)
    node[i] = stack[i];
}

static void treehash_update(treehash_inst *treehash, bds_state *state, const unsigned char *sk_seed, const xmssfast_params *params, const unsigned char *pub_seed, const uint32_t addr[8]) {
  int n = params->n;

  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t  node_addr[8];
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
  gen_leaf_wots(nodebuffer, sk_seed, params, pub_seed, ltree_addr, ots_addr);
  while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset-1] == nodeheight) {
    memcpy(nodebuffer + n, nodebuffer, n);
    memcpy(nodebuffer, state->stack + (state->stackoffset-1)*n, n);
    setTreeHeight(node_addr, nodeheight);
    setTreeIndex(node_addr, (treehash->next_idx >> (nodeheight+1)));
    hash_h(nodebuffer, nodebuffer, pub_seed, node_addr, n);
    nodeheight++;
    treehash->stackusage--;
    state->stackoffset--;
  }
  if (nodeheight == treehash->h) { // this also implies stackusage == 0
    memcpy(treehash->node, nodebuffer, n);
    treehash->completed = 1;
  }
  else {
    memcpy(state->stack + state->stackoffset*n, nodebuffer, n);
    treehash->stackusage++;
    state->stacklevels[state->stackoffset] = nodeheight;
    state->stackoffset++;
    treehash->next_idx++;
  }
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void validate_authpath(unsigned char *root, const unsigned char *leaf, unsigned long leafidx, const unsigned char *authpath, const xmssfast_params *params, const unsigned char *pub_seed, uint32_t addr[8])
{
  unsigned int n = params->n;

  uint32_t i, j;
  unsigned char buffer[2*n];

  // If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
  // Otherwise, it is the other way around
  if (leafidx & 1) {
    for (j = 0; j < n; j++)
      buffer[n+j] = leaf[j];
    for (j = 0; j < n; j++)
      buffer[j] = authpath[j];
  }
  else {
    for (j = 0; j < n; j++)
      buffer[j] = leaf[j];
    for (j = 0; j < n; j++)
      buffer[n+j] = authpath[j];
  }
  authpath += n;

  for (i=0; i < params->h-1; i++) {
    setTreeHeight(addr, i);
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    if (leafidx&1) {
      hash_h(buffer+n, buffer, pub_seed, addr, n);
      for (j = 0; j < n; j++)
        buffer[j] = authpath[j];
    }
    else {
      hash_h(buffer, buffer, pub_seed, addr, n);
      for (j = 0; j < n; j++)
        buffer[j+n] = authpath[j];
    }
    authpath += n;
  }
  setTreeHeight(addr, (params->h-1));
  leafidx >>= 1;
  setTreeIndex(addr, leafidx);
  hash_h(root, buffer, pub_seed, addr, n);
}

/**
 * Performs one treehash update on the instance that needs it the most.
 * Returns 1 if such an instance was not found
 **/
static char bds_treehash_update(bds_state *state, unsigned int updates, const unsigned char *sk_seed, const xmssfast_params *params, unsigned char *pub_seed, const uint32_t addr[8]) {
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
    treehash_update(&(state->treehash[level]), state, sk_seed, params, pub_seed, addr);
    used++;
  }
  return updates - used;
}

/**
 * Updates the state (typically NEXT_i) by adding a leaf and updating the stack
 * Returns 1 if all leaf nodes have already been processed
 **/
static char bds_state_update(bds_state *state, const unsigned char *sk_seed, const xmssfast_params *params, unsigned char *pub_seed, const uint32_t addr[8]) {
  uint32_t ltree_addr[8];
  uint32_t node_addr[8];
  uint32_t ots_addr[8];

  int n = params->n;
  int h = params->h;
  int k = params->k;

  int nodeh;
  int idx = state->next_leaf;
  if (idx == 1 << h) {
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

  gen_leaf_wots(state->stack+state->stackoffset*n, sk_seed, params, pub_seed, ltree_addr, ots_addr);

  state->stacklevels[state->stackoffset] = 0;
  state->stackoffset++;
  if (h - k > 0 && idx == 3) {
    memcpy(state->treehash[0].node, state->stack+state->stackoffset*n, n);
  }
  while (state->stackoffset>1 && state->stacklevels[state->stackoffset-1] == state->stacklevels[state->stackoffset-2]) {
    nodeh = state->stacklevels[state->stackoffset-1];
    if (idx >> nodeh == 1) {
      memcpy(state->auth + nodeh*n, state->stack+(state->stackoffset-1)*n, n);
    }
    else {
      if (nodeh < h - k && idx >> nodeh == 3) {
        memcpy(state->treehash[nodeh].node, state->stack+(state->stackoffset-1)*n, n);
      }
      else if (nodeh >= h - k) {
        memcpy(state->retain + ((1 << (h - 1 - nodeh)) + nodeh - h + (((idx >> nodeh) - 3) >> 1)) * n, state->stack+(state->stackoffset-1)*n, n);
      }
    }
    setTreeHeight(node_addr, state->stacklevels[state->stackoffset-1]);
    setTreeIndex(node_addr, (idx >> (state->stacklevels[state->stackoffset-1]+1)));
    hash_h(state->stack+(state->stackoffset-2)*n, state->stack+(state->stackoffset-2)*n, pub_seed, node_addr, n);

    state->stacklevels[state->stackoffset-2]++;
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
static void bds_round(bds_state *state, const unsigned long leaf_idx, const unsigned char *sk_seed, const xmssfast_params *params, unsigned char *pub_seed, uint32_t addr[8])
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
  uint32_t  node_addr[8];
  // only copy layer and tree address parts
  memcpy(ots_addr, addr, 12);
  // type = ots
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);

  for (i = 0; i < h; i++) {
    if (! ((leaf_idx >> i) & 1)) {
      tau = i;
      break;
    }
  }

  if (tau > 0) {
    memcpy(buf,     state->auth + (tau-1) * n, n);
    // we need to do this before refreshing state->keep to prevent overwriting
    memcpy(buf + n, state->keep + ((tau-1) >> 1) * n, n);
  }
  if (!((leaf_idx >> (tau + 1)) & 1) && (tau < h - 1)) {
    memcpy(state->keep + (tau >> 1)*n, state->auth + tau*n, n);
  }
  if (tau == 0) {
    setLtreeADRS(ltree_addr, leaf_idx);
    setOTSADRS(ots_addr, leaf_idx);
    gen_leaf_wots(state->auth, sk_seed, params, pub_seed, ltree_addr, ots_addr);
  }
  else {
    setTreeHeight(node_addr, (tau-1));
    setTreeIndex(node_addr, leaf_idx >> tau);
    hash_h(state->auth + tau * n, buf, pub_seed, node_addr, n);
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
int xmssfast_Genkeypair(unsigned char *pk, unsigned char *sk, bds_state *state, unsigned char *seed, unsigned char h)
{
  if(h & 1){
    printf("Not a valid h, only even numbers supported! Try again with an even number");
    return -1;
  }
  xmssfast_set_params(&paramsfast, 32, h, 16, 2);
  unsigned int k = paramsfast.k;
  unsigned int n = paramsfast.n;

  // Set idx = 0
  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;
  // Init SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte)
  //randombytes(sk+4, 3*n);
  // Copy PUB_SEED to public key
  unsigned char randombits[3 * n];
  shake256(randombits, 3 * n, seed, 48);  // FIXME: seed size has been hardcoded to 48
  size_t rnd = 96;
  size_t pks = 32;
  memcpy(sk + 4, randombits, rnd);
  memcpy(pk + n, sk + 4 + 2 * n, pks);

  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // Compute root
  treehash_setup(pk, paramsfast.h, 0, state, sk+4, &paramsfast, sk+4+2*n, addr);
  // copy root to sk
  memcpy(sk+4+3*n, pk, pks);
  return 0;
}

int xmssfast_update(unsigned char *sk, bds_state *state, unsigned long h, unsigned long new_idx) {
  //unsigned long idxkey=0;
  xmssfast_set_params(&paramsfast, 32, h, 16, 2);
  unsigned long k = 2;
  //idxkey = ((unsigned long)sig_msg[0] << 24) | ((unsigned long)sig_msg[1] << 16) | ((unsigned long)sig_msg[2] << 8) | sig_msg[3];
  uint32_t idxkey =
          ((unsigned long) sk[0] << 24) | ((unsigned long) sk[1] << 16) | ((unsigned long) sk[2] << 8) | sk[3];
  if (idxkey >= new_idx) {
    return -1;
    //the secret key is updated more than the blockchain, so all fine
  } else{
    uint32_t idx = new_idx;
    //update secret key index
    sk[0] = ((idx) >> 24) & 255;
    sk[1] = ((idx) >> 16) & 255;
    sk[2] = ((idx) >> 8) & 255;
    sk[3] = (idx) & 255;

    unsigned char sk_seed[32];
    memcpy(sk_seed, sk+4, 32);

    unsigned char pub_seed[32];
    memcpy(pub_seed, sk+4+2*32, 32);

    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    for(int j = idxkey; j < new_idx ; j++){
      if (j < (1U << h) - 1) {
        bds_round(state, j, sk_seed, &paramsfast, pub_seed, ots_addr);
        bds_treehash_update(state, (h - k) >> 1, sk_seed, &paramsfast, pub_seed, ots_addr);
      }else{

      }
    }

    return 0;
  }
}


int xmssfast_Signmsg(unsigned char *sk, bds_state *state, unsigned char *sig_msg, unsigned char *msg, unsigned long long msglen, unsigned char h)
{
  xmssfast_set_params(&paramsfast, 32, h, 16, 2);
  unsigned int n = paramsfast.n;
  unsigned int k = paramsfast.k;
  uint16_t i = 0;

  // Extract SK
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  unsigned char sk_seed[n];
  memcpy(sk_seed, sk+4, n);
  unsigned char sk_prf[n];
  memcpy(sk_prf, sk+4+n, n);
  unsigned char pub_seed[n];
  memcpy(pub_seed, sk+4+2*n, n);
  
  // index as 32 bytes string
  unsigned char idx_bytes_32[32];
  to_byte(idx_bytes_32, idx, 32);
  
  unsigned char hash_key[3*n]; 
  
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
  prf(R, idx_bytes_32, sk_prf, n);
  // Generate hash key (R || root || idx)
  memcpy(hash_key, R, n);
  memcpy(hash_key+n, sk+4+3*n, n);
  to_byte(hash_key+2*n, idx, n);
  // Then use it for message digest
  h_msg(msg_h, msg, msglen, hash_key, 3*n, n);

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
  wots_sign(sig_msg, msg_h, ots_seed, &(paramsfast.wots_par), pub_seed, ots_addr);
  sig_msg += paramsfast.wots_par.keysize;
  sig_msg_len += paramsfast.wots_par.keysize;

  // the auth path was already computed during the previous round
  memcpy(sig_msg, state->auth, h*n);

  if (idx < (1U << h) - 1) {
    bds_round(state, idx, sk_seed, &paramsfast, pub_seed, ots_addr);
    bds_treehash_update(state, (h - k) >> 1, sk_seed, &paramsfast, pub_seed, ots_addr);
  }

  sig_msg += paramsfast.h*n;
  sig_msg_len += paramsfast.h*n;

  //Whipe secret elements?
  //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  //  memcpy(sig_msg, msg, msglen);
  //*sig_msg_len += msglen;
  //printf("%d",sig_msg_len);
  return 0;
}

int xmssfast_Verifysig(unsigned char *msg, unsigned long long msglen, unsigned char *sig_msg, const unsigned char *pk, unsigned char h)
{
  xmssfast_set_params(&paramsfast, 32, h, 16,2);
  unsigned int n = paramsfast.n;

  unsigned long long sig_msg_len = 4 + 32 + 67 * 32 + h * 32;
  unsigned long long i, m_len;
  unsigned long idx=0;
  unsigned char wots_pk[paramsfast.wots_par.keysize];
  unsigned char pkhash[n];
  unsigned char root[n];
  unsigned char msg_h[n];
  unsigned char hash_key[3*n];

  unsigned char pub_seed[n];
  memcpy(pub_seed, pk+n, n);

  // Init addresses
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t ltree_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t node_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  setType(ots_addr, 0);
  setType(ltree_addr, 1);
  setType(node_addr, 2);

  // Extract index
  idx = ((unsigned long)sig_msg[0] << 24) | ((unsigned long)sig_msg[1] << 16) | ((unsigned long)sig_msg[2] << 8) | sig_msg[3];
  //printf("verify:: idx = %lu\n", idx);
  
  // Generate hash key (R || root || idx)
  memcpy(hash_key, sig_msg+4,n);
  memcpy(hash_key+n, pk, n);
  to_byte(hash_key+2*n, idx, n);
  
  sig_msg += (n+4);
  sig_msg_len -= (n+4);

  // hash message 
  unsigned long long tmp_sig_len = paramsfast.wots_par.keysize+paramsfast.h*n;
  m_len = sig_msg_len - tmp_sig_len;
  h_msg(msg_h, msg, msglen, hash_key, 3*n, n);

  //-----------------------
  // Verify signature
  //-----------------------

  // Prepare Address
  setOTSADRS(ots_addr, idx);
  // Check WOTS signature
  wots_pkFromSig(wots_pk, sig_msg, msg_h, &(paramsfast.wots_par), pub_seed, ots_addr);

  sig_msg += paramsfast.wots_par.keysize;
  sig_msg_len -= paramsfast.wots_par.keysize;

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx);
  l_tree(pkhash, wots_pk, &paramsfast, pub_seed, ltree_addr);

  // Compute root
  validate_authpath(root, pkhash, idx, sig_msg, &paramsfast, pub_seed, node_addr);

  sig_msg += paramsfast.h*n;
  sig_msg_len -= paramsfast.h*n;

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