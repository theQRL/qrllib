// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <cstddef>

void get_seed(eHashFunction hash_func,
              unsigned char *seed,
              const unsigned char *sk_seed,
              int n,
              uint32_t addr[8]);
