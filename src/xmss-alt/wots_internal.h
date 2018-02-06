// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef WOTS_INTERNAL_H
#define WOTS_INTERNAL_H

#include <cstdint>
#include "eHashFunctions.h"

void expand_seed(eHashFunction hash_func,
                 unsigned char *outseeds,
                 const unsigned char *inseed,
                 const uint32_t n,
                 const uint32_t len);

#endif
