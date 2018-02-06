// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#include <stdint.h> // NOLINT
#include <stddef.h> // NOLINT

extern "C"
{
void sha2_256(uint8_t *hashed_output,
              uint8_t *input,
              size_t count);
};
