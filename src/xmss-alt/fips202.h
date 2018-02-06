// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

#ifndef FIPS202_H
#define FIPS202_H

#include <cstdint>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

void shake128(unsigned char *out,
              unsigned long long outlen,
              const unsigned char *in,
              unsigned long long inlen);

void shake256(unsigned char *out,
              unsigned long long outlen,
              const unsigned char *in,
              unsigned long long inlen);

#endif
