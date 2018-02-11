// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
wots.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef WOTS_H
#define WOTS_H

#include <cstdint>
#include "eHashFunctions.h"
#include "wots_params.h"

/**
 * WOTS key generation. Takes a 32byte seed for the secret key, expands it to a full WOTS secret key and computes the corresponding public key. 
 * For this it takes the seed pub_seed which is used to generate bitmasks and hash keys and the address of this WOTS key pair addr
 * 
 * params, must have been initialized before using wots_set params for params ! This is not done in this function
 * 
 * Places the computed public key at address pk.
 */
void wots_pkgen(eHashFunction hash_func,
                unsigned char *pk,
                const unsigned char *sk,
                const wots_params *params,
                const unsigned char *pub_seed,
                uint32_t addr[8]);

/**
 * Takes a m-byte message and the 32-byte seed for the secret key to compute a signature that is placed at "sig".
 *  
 */
void wots_sign(eHashFunction hash_func,
               unsigned char *sig,
               const unsigned char *msg,
               const unsigned char *sk,
               const wots_params *params,
               const unsigned char *pub_seed,
               uint32_t addr[8]);

/**
 * Takes a WOTS signature, a m-byte message and computes a WOTS public key that it places at pk.
 * 
 */
void wots_pkFromSig(eHashFunction hash_func,
                    unsigned char *pk,
                    const unsigned char *sig,
                    const unsigned char *msg,
                    const wots_params *wotsParams,
                    const unsigned char *pub_seed,
                    uint32_t addr[8]);

#endif
