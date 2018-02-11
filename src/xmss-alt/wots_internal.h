// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef WOTS_INTERNAL_H
#define WOTS_INTERNAL_H

#include <cstdint>
#include "eHashFunctions.h"
#include "wots_params.h"

void expand_seed(eHashFunction hash_func,
                 unsigned char *outseeds,
                 const unsigned char *inseed,
                 const uint32_t n,
                 const uint32_t len);

void gen_chain(eHashFunction hash_func,
               unsigned char *out,
               const unsigned char *in,
               unsigned int start,
               unsigned int steps,
               const wots_params *params,
               const unsigned char *pub_seed,
               uint32_t addr[8]);
#endif
