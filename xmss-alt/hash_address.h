// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Based on the public domain XMSS reference implementation
// by Andreas Hülsing and Joost Rijneveld
/*
hash_address.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include <cstdint>

// FIXME: Get rid of this. Use unions

void setLayerADRS(uint32_t adrs[8], uint32_t layer);

void setTreeADRS(uint32_t adrs[8], uint64_t tree);

void setType(uint32_t adrs[8], uint32_t type);

void setKeyAndMask(uint32_t adrs[8], uint32_t keyAndMask);

// OTS

void setOTSADRS(uint32_t adrs[8], uint32_t ots);

void setChainADRS(uint32_t adrs[8], uint32_t chain);

void setHashADRS(uint32_t adrs[8], uint32_t hash);

// L-tree

void setLtreeADRS(uint32_t adrs[8], uint32_t ltree);

// Hash Tree & L-tree

void setTreeHeight(uint32_t adrs[8], uint32_t treeHeight);

void setTreeIndex(uint32_t adrs[8], uint32_t treeIndex);



