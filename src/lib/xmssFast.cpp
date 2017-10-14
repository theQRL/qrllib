// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <xmss_params.h>
#include "xmssFast.h"
#include "algsxmss_fast.h"
#include "xmss_common.h"

XmssFast::XmssFast(const TSEED &seed, unsigned char height): XmssBase(seed, height)
{
//    PK format
//    32 root address
//    32 pub_seed
//
//    SK format
//    4  idx
//    32 sk_seed
//    32 sk_prf
//    32 pub_seed
//    32 root
// TODO: Use a union? to operated on partial fields

    // FIXME: Inconsistency here
    _sk = TKEY(132, 0);
    auto tmp = TKEY(64, 0);
    xmss_set_params(&params,
                    32,
                    _height,
                    16,
                    2 );

    // FIXME: This needs refactoring
    const uint32_t n = params.n;
    const uint32_t h = params.h;
    const uint32_t k = params.k;

    _stackoffset = 0;
    _stack = std::vector<unsigned char>((h+1)*n);
    _stacklevels = std::vector<unsigned char>(h+1);
    _auth = std::vector<unsigned char>(h*n);
    _keep = std::vector<unsigned char>((h >> 1)*n);
    _treehash = std::vector<treehash_inst>(h-k);
    _th_nodes = std::vector<unsigned char>((h-k)*n);
    _retain = std::vector<unsigned char>(((1 << k) - k - 1)*n);

    for (int i = 0; i < h-k; i++)
    {
        _treehash[i].node = &_th_nodes[n*i];
    }

    xmss_set_bds_state(&_state,
                       _stack.data(),
                       _stackoffset,
                       _stacklevels.data(),
                       _auth.data(),
                       _keep.data(),
                       _treehash.data(),
                       _retain.data(),
                       0);

    xmssfast_Genkeypair(&params,
                        tmp.data(),
                        _sk.data(),
                        &_state,
                        _seed.data());
}

unsigned int XmssFast::setIndex(unsigned int new_index)
{
    xmssfast_update(&params,
                    _sk.data(),
                    &_state,
                    new_index);

    return new_index;
}

TSIGNATURE XmssFast::sign(const TMESSAGE &message)
{
    // TODO: Fix constness in library
    auto signature = TSIGNATURE(getSignatureSize(), 0);

    auto index = getIndex();
    setIndex( index );

    xmssfast_Signmsg(&params,
                     _sk.data(),
                     &_state,
                     signature.data(),
                     static_cast<TMESSAGE>(message).data(),
                     message.size());

    return signature;
}
