// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <algorithm>
#include <utility>
#include <xmss-alt/xmss_params.h>
#include <crypto/secure_memory.h>
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
    if (!_sk.empty()) {
        validateBaseState();
        if (getIndex() != 0) {
            throw std::invalid_argument(
                "cannot reinitialize an XMSS signing key after index zero");
        }
    }
    if (_seed.size() != XmssValidation::SEED_SIZE) {
        throw std::logic_error("Invalid XMSS seed state");
    }
    XmssValidation::height(_height);
    XmssValidation::hashFunction(_hashFunction);
    XmssValidation::addressFormat(_addrFormatType);
    XmssValidation::wots(wotsParamW);
    const uint32_t k = 2;
    const uint32_t w = wotsParamW;
    const uint32_t n = 32;

    if (k >= _height || (_height - k) % 2) {
        throw std::invalid_argument("For BDS traversal, H - K must be even, with H > K >= 2!");
    }

    xmss_params replacement_params{};
    xmss_set_params(&replacement_params, n, _height, w, k);
    if (!xmss_params_are_valid(&replacement_params)) {
        throw std::invalid_argument("Invalid XMSS parameters");
    }

    TKEY replacement_sk(XmssValidation::SECRET_KEY_SIZE, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> replacement_sk_guard(replacement_sk);
    TKEY tmp(64, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> tmp_guard(tmp);

    std::vector<unsigned char> replacement_stack((_height + 1) * n);
    qrllib::secure_memory::WipeGuard<unsigned char> stack_guard(replacement_stack);
    std::vector<unsigned char> replacement_stacklevels(_height + 1);
    qrllib::secure_memory::WipeGuard<unsigned char> stacklevels_guard(replacement_stacklevels);
    std::vector<unsigned char> replacement_auth(_height * n);
    qrllib::secure_memory::WipeGuard<unsigned char> auth_guard(replacement_auth);
    std::vector<unsigned char> replacement_keep((_height >> 1) * n);
    qrllib::secure_memory::WipeGuard<unsigned char> keep_guard(replacement_keep);
    std::vector<treehash_inst> replacement_treehash(_height - k);
    qrllib::secure_memory::WipeGuard<treehash_inst> treehash_guard(replacement_treehash);
    std::vector<unsigned char> replacement_th_nodes((_height - k) * n);
    qrllib::secure_memory::WipeGuard<unsigned char> th_nodes_guard(replacement_th_nodes);
    std::vector<unsigned char> replacement_retain(((1U << k) - k - 1) * n);
    qrllib::secure_memory::WipeGuard<unsigned char> retain_guard(replacement_retain);

    for (size_t i = 0; i < replacement_treehash.size(); ++i) {
        replacement_treehash[i].node = replacement_th_nodes.data() + n * i;
    }

    bds_state replacement_state{};
    qrllib::secure_memory::RangeWipeGuard state_guard(
        &replacement_state, sizeof(replacement_state));
    xmss_set_bds_state(&replacement_state,
                       replacement_stack.data(),
                       0,
                       replacement_stacklevels.data(),
                       replacement_auth.data(),
                       replacement_keep.data(),
                       replacement_treehash.data(),
                       replacement_retain.data(),
                       0);

    if (xmssfast_Genkeypair(_hashFunction,
                            &replacement_params,
                            tmp.data(),
                            replacement_sk.data(),
                            &replacement_state,
                            _seed.data()) != 0) {
        throw std::runtime_error("XMSS key generation failed");
    }

    // Publish the fully built replacement only after every allocation and the
    // backend key generation have succeeded. The guards erase the displaced
    // buffers when they leave scope.
    wipeState();
    qrllib::secure_memory::wipe_and_swap(_sk, replacement_sk);
    qrllib::secure_memory::wipe_and_swap(_stack, replacement_stack);
    qrllib::secure_memory::wipe_and_swap(_stacklevels, replacement_stacklevels);
    qrllib::secure_memory::wipe_and_swap(_auth, replacement_auth);
    qrllib::secure_memory::wipe_and_swap(_keep, replacement_keep);
    qrllib::secure_memory::wipe_and_swap(_treehash, replacement_treehash);
    qrllib::secure_memory::wipe_and_swap(_th_nodes, replacement_th_nodes);
    qrllib::secure_memory::wipe_and_swap(_retain, replacement_retain);
    params = replacement_params;
    _state = replacement_state;
    _stackoffset = replacement_state.stackoffset;
    rebindState();
    try {
        validateState();
    } catch (...) {
        wipeState();
        qrllib::secure_memory::wipe(_sk);
        throw;
    }
}

void XmssFast::rebindState()
{
    const uint32_t n = params.n;

    for (size_t i = 0; i < _treehash.size(); i++) {
        const auto offset = static_cast<size_t>(n) * i;
        _treehash[i].node = offset + n <= _th_nodes.size()
                                ? _th_nodes.data() + offset
                                : nullptr;
    }

    _state.stack = _stack.data();
    _state.stacklevels = _stacklevels.data();
    _state.auth = _auth.data();
    _state.keep = _keep.data();
    _state.treehash = _treehash.data();
    _state.retain = _retain.data();
}

void XmssFast::validateState() const
{
    validateBaseState();
    XmssValidation::wots(params.wots_par.w);
    if (!xmss_params_are_valid(&params) ||
        params.n != XmssValidation::N ||
        params.h != _height ||
        params.k != XmssValidation::BDS_K ||
        _stack.size() != (static_cast<size_t>(_height) + 1) * params.n ||
        _stacklevels.size() != static_cast<size_t>(_height) + 1 ||
        _auth.size() != static_cast<size_t>(_height) * params.n ||
        _keep.size() != (static_cast<size_t>(_height) >> 1) * params.n ||
        _treehash.size() != static_cast<size_t>(_height - params.k) ||
        _th_nodes.size() != static_cast<size_t>(_height - params.k) * params.n ||
        _retain.size() != ((size_t{1} << params.k) - params.k - 1) * params.n) {
        throw std::logic_error("Invalid XMSS traversal state");
    }
}

XmssFast::XmssFast(const XmssFast& other)
    : XmssBase(other),
      _state{},
      _stackoffset(other._stackoffset),
      _stack(),
      _stacklevels(),
      _auth(),
      _keep(),
      _treehash(),
      _th_nodes(),
      _retain()
{
    other.validateState();
    // Build guarded replacements so a later allocation failure cannot free an
    // earlier secret-bearing copy without first erasing it.
    std::vector<unsigned char> replacement_stack(other._stack.size());
    qrllib::secure_memory::WipeGuard<unsigned char> stack_guard(replacement_stack);
    std::copy(other._stack.begin(), other._stack.end(), replacement_stack.begin());
    std::vector<unsigned char> replacement_stacklevels(other._stacklevels.size());
    qrllib::secure_memory::WipeGuard<unsigned char> stacklevels_guard(replacement_stacklevels);
    std::copy(other._stacklevels.begin(), other._stacklevels.end(), replacement_stacklevels.begin());
    std::vector<unsigned char> replacement_auth(other._auth.size());
    qrllib::secure_memory::WipeGuard<unsigned char> auth_guard(replacement_auth);
    std::copy(other._auth.begin(), other._auth.end(), replacement_auth.begin());
    std::vector<unsigned char> replacement_keep(other._keep.size());
    qrllib::secure_memory::WipeGuard<unsigned char> keep_guard(replacement_keep);
    std::copy(other._keep.begin(), other._keep.end(), replacement_keep.begin());
    std::vector<treehash_inst> replacement_treehash(other._treehash.size());
    qrllib::secure_memory::WipeGuard<treehash_inst> treehash_guard(replacement_treehash);
    std::copy(other._treehash.begin(), other._treehash.end(), replacement_treehash.begin());
    std::vector<unsigned char> replacement_th_nodes(other._th_nodes.size());
    qrllib::secure_memory::WipeGuard<unsigned char> th_nodes_guard(replacement_th_nodes);
    std::copy(other._th_nodes.begin(), other._th_nodes.end(), replacement_th_nodes.begin());
    std::vector<unsigned char> replacement_retain(other._retain.size());
    qrllib::secure_memory::WipeGuard<unsigned char> retain_guard(replacement_retain);
    std::copy(other._retain.begin(), other._retain.end(), replacement_retain.begin());

    _stack.swap(replacement_stack);
    _stacklevels.swap(replacement_stacklevels);
    _auth.swap(replacement_auth);
    _keep.swap(replacement_keep);
    _treehash.swap(replacement_treehash);
    _th_nodes.swap(replacement_th_nodes);
    _retain.swap(replacement_retain);
    _state = other._state;
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
    other.wipeState();
}

XmssFast::~XmssFast()
{
    wipeState();
}

void XmssFast::wipeState() noexcept
{
    qrllib::secure_memory::wipe(_stack);
    qrllib::secure_memory::wipe(_stacklevels);
    qrllib::secure_memory::wipe(_auth);
    qrllib::secure_memory::wipe(_keep);
    qrllib::secure_memory::wipe(_treehash);
    qrllib::secure_memory::wipe(_th_nodes);
    qrllib::secure_memory::wipe(_retain);
    qrllib::secure_memory::secure_zero(&_state, sizeof(_state));
    _stackoffset = 0;
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
        wipeState();
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
        other.wipeState();
    }
    return *this;
}

unsigned int XmssFast::setIndex(unsigned int new_index)
{
    validateState();
    const auto current = getIndex();
    const auto count = getNumberSignatures();
    if (new_index > count) {
        throw std::invalid_argument("index too high");
    }
    if (new_index < current) {
        throw std::invalid_argument("cannot rewind");
    }
    rebindState();
    if (xmssfast_update(_hashFunction,
                        &params,
                        _sk.data(),
                        &_state,
                        new_index) != 0) {
        throw std::runtime_error("XMSS state update failed");
    }

    return new_index;
}

TSIGNATURE XmssFast::sign(const TMESSAGE &message)
{
    validateState();
    rebindState();
    if (getIndex() >= getNumberSignatures()) {
        throw std::invalid_argument("index too high");
    }
    auto signature = TSIGNATURE(getSignatureSize(params.wots_par.w), 0);
    qrllib::secure_memory::WipeGuard<uint8_t> signature_guard(signature);

    auto index = getIndex();
    setIndex(index);

    if (xmssfast_Signmsg(_hashFunction,
                         &params,
                         _sk.data(),
                         &_state,
                         signature.data(),
                         message.data(),
                         message.size()) != 0) {
        throw std::runtime_error("XMSS signing failed");
    }

    signature_guard.release();
    return signature;
}
