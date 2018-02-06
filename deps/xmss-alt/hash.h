// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
hash.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
/*
This code was taken from the XMSS reference implementation by Andreas Hülsing and Joost Rijneveld and is public domain.
*/

#ifndef HASH_H
#define HASH_H

#include <cstdint>

unsigned char *addr_to_byte(unsigned char *bytes, const uint32_t addr[8]);

int prf(eHashFunction hash_func,
        unsigned char *out, const unsigned char *in, const unsigned char *key, unsigned int keylen);

int h_msg(eHashFunction hash_func,
          unsigned char *out, const unsigned char *in, unsigned long long inlen,
          const unsigned char *key, unsigned int keylen, unsigned int n);

int hash_h(eHashFunction hash_func,
           unsigned char *out, const unsigned char *in, const unsigned char *pub_seed,
           uint32_t addr[8], unsigned int n);

int hash_f(eHashFunction hash_func,
           unsigned char *out, const unsigned char *in, const unsigned char *pub_seed,
           uint32_t addr[8], unsigned int n);

#endif
