/*
xmss_fast.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "wots.h"
#include <cstddef>

typedef struct{
  unsigned int level;
  unsigned long long subtree;
  unsigned int subleaf;
} leafaddr;

typedef struct{
  wots_params wots_par;
  unsigned int n;
  unsigned int h;
  unsigned int k;
} xmssfast_params;

typedef struct{
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
void xmss_set_bds_state(bds_state *state, unsigned char *stack, int stackoffset, unsigned char *stacklevels, unsigned char *auth, unsigned char *keep, treehash_inst *treehash, unsigned char *retain, int next_leaf);
/**
 * Initializes parameter set.
 * Needed, for any of the other methods.
 */
int xmss_set_params(xmssfast_params *params, int n, int h, int w, int k);
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
int xmssfast_Genkeypair(unsigned char *pk, unsigned char *sk, bds_state *state, xmssfast_params *params);
/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmssfast_Signmsg(unsigned char *sk, bds_state *state, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg,unsigned long long msglen, const xmssfast_params *params);
/**
 * Verifies a given message signature pair under a given public key.
 * 
 * Note: msg and msglen are pure outputs which carry the message in case verification succeeds. The (input) message is assumed to be within sig_msg which has the form (sig||msg). 
 */
int xmssfast_Verifysig(unsigned char *msg,unsigned long long *msglen, const unsigned char *sig_msg,unsigned long long sig_msg_len, const unsigned char *pk, const xmssfast_params *params);

