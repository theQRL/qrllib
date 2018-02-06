// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "shasha.h"
#include <PicoSHA2/picosha2.h>

void sha2_256(uint8_t *hashed_output,
              uint8_t *input,
              size_t count)
{
    picosha2::hash256(input, input+count, hashed_output, hashed_output+32);
}
