// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <utility>
#include <xmss-alt/xmss_params.h>
#include "xmssFast.h"

XmssFast::XmssFast(const TSEED &seed,
                   unsigned char height,
                   eHashFunction hashFunction,
                   eAddrFormatType addrFormatType)
    : XmssBase(seed, height, hashFunction, addrFormatType)
{
    initialize_tree();
}

XmssFast::XmssFast(const TSEED& extended_seed)
    : XmssBase(extended_seed)
{
    initialize_tree();
}

void XmssFast::initialize_tree(uint32_t wotsParamW)
{
    _sk = TKEY(132, 0);
    auto tmp = TKEY(64, 0);

    const uint32_t k = 2;
    const uint32_t w = wotsParamW;
    const uint32_t n = 32;

    if (k >= _height || (_height - k) % 2) {
        throw std::invalid_argument("For BDS traversal, H - K must be even, with H > K >= 2!");
    }

    xmss_set_params(&params, n, _height, w, k);

    _stackoffset = 0;
    _stack = std::vector<unsigned char>((_height + 1) * n);
    _stacklevels = std::vector<unsigned char>(_height + 1);
    _auth = std::vector<unsigned char>(_height * n);
    _keep = std::vector<unsigned char>((_height >> 1) * n);
    _treehash = std::vector<treehash_inst>(_height - k);
    _th_nodes = std::vector<unsigned char>((_height - k) * n);
    _retain = std::vector<unsigned char>(((1 << k) - k - 1) * n);

    xmss_set_bds_state(&_state,
            _stack.data(),
            _stackoffset,
            _stacklevels.data(),
            _auth.data(),
            _keep.data(),
            _treehash.data(),
            _retain.data(),
            0);
    rebindState();

    xmssfast_Genkeypair(_hashFunction,
            &params,
            tmp.data(),
            _sk.data(),
            &_state,
            _seed.data());
}

void XmssFast::rebindState()
{
    const uint32_t n = params.n;

    for (size_t i = 0; i < _treehash.size(); i++) {
        _treehash[i].node = &_th_nodes[n * i];
    }

    _state.stack = _stack.data();
    _state.stacklevels = _stacklevels.data();
    _state.auth = _auth.data();
    _state.keep = _keep.data();
    _state.treehash = _treehash.data();
    _state.retain = _retain.data();
}

XmssFast::XmssFast(const XmssFast& other)
    : XmssBase(other),
      _state(other._state),
      _stackoffset(other._stackoffset),
      _stack(other._stack),
      _stacklevels(other._stacklevels),
      _auth(other._auth),
      _keep(other._keep),
      _treehash(other._treehash),
      _th_nodes(other._th_nodes),
      _retain(other._retain)
{
    rebindState();
}

XmssFast::XmssFast(XmssFast&& other) noexcept
    : XmssBase(std::move(other)),
      _state(other._state),
      _stackoffset(other._stackoffset),
      _stack(std::move(other._stack)),
      _stacklevels(std::move(other._stacklevels)),
      _auth(std::move(other._auth)),
      _keep(std::move(other._keep)),
      _treehash(std::move(other._treehash)),
      _th_nodes(std::move(other._th_nodes)),
      _retain(std::move(other._retain))
{
    rebindState();
    other.rebindState();
}

XmssFast& XmssFast::operator=(const XmssFast& other)
{
    if (this != &other) {
        // Leave this signer intact if copying any buffer throws.
        XmssFast copy(other);
        *this = std::move(copy);
    }
    return *this;
}

XmssFast& XmssFast::operator=(XmssFast&& other) noexcept
{
    if (this != &other) {
        XmssBase::operator=(std::move(other));
        _state = other._state;
        _stackoffset = other._stackoffset;
        _stack = std::move(other._stack);
        _stacklevels = std::move(other._stacklevels);
        _auth = std::move(other._auth);
        _keep = std::move(other._keep);
        _treehash = std::move(other._treehash);
        _th_nodes = std::move(other._th_nodes);
        _retain = std::move(other._retain);
        rebindState();
        other.rebindState();
    }
    return *this;
}

unsigned int XmssFast::setIndex(unsigned int new_index)
{
    xmssfast_update(_hashFunction,
                    &params,
                    _sk.data(),
                    &_state,
                    new_index);

    return new_index;
}

TSIGNATURE XmssFast::sign(const TMESSAGE &message)
{
    auto signature = TSIGNATURE(getSignatureSize(params.wots_par.w), 0);

    auto index = getIndex();
    setIndex(index);

    if (xmssfast_Signmsg(_hashFunction,
                         &params,
                         _sk.data(),
                         &_state,
                         signature.data(),
                         static_cast<TMESSAGE>(message).data(),
                         message.size()) != 0) {
        throw std::runtime_error("XMSS signing failed");
    }

    return signature;
}
