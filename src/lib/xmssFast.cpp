// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
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

    const uint32_t n = 48;
    const uint32_t h = _height;

    // FIXME: This needs refactoring
    _stackoffset = 0;
    _stack = std::vector<unsigned char>((h+1)*n);
    _stacklevels = std::vector<unsigned char>(h+1);
    _auth = std::vector<unsigned char>(h*n);
    _keep = std::vector<unsigned char>((h >> 1)*n);
    _treehash = std::vector<treehash_inst>(h-_k);
    _th_nodes = std::vector<unsigned char>((h-_k)*n);
    _retain = std::vector<unsigned char>(((1 << _k) - _k - 1)*n);
    for (int i = 0; i < h-_k; i++)
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

    _sk = TKEY(132, 0);
    auto tmp = TKEY(64, 0);
    xmssfast_Genkeypair(tmp.data(),
                        _sk.data(),
                        &_state,
                        _seed.data(),
                        _height);
}

unsigned int XmssFast::setIndex(unsigned int new_index)
{
    xmssfast_update(_sk.data(), &_state, _height, new_index);
    return new_index;
}

TSIGNATURE XmssFast::sign(const TMESSAGE &message)
{
    // TODO: Fix constness in library
    auto signature = TSIGNATURE(getSignatureSize(), 0);

    auto index = getIndex();
    setIndex( index );

    xmssfast_Signmsg(_sk.data(),
                     &_state,
                     signature.data(),
                     static_cast<TMESSAGE>(message).data(),
                     message.size(),
                     _height);

    return signature;
}
