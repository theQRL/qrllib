// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <crypto/secure_memory.h>
#include "xmssFast.h"
#include "xmssPool.h"
#include "hashing.h"
#include "misc.h"

XmssPool::XmssPool(const TSEED &base_seed, uint8_t height, const size_t starting_index, size_t pool_size) :
        _base_seed(),
        _height(height),
        _current_index(starting_index),
        _pool_size(pool_size) {
    if (base_seed.size() != XmssValidation::SEED_SIZE) {
        throw std::invalid_argument("XMSS pool base seed must be 48 bytes");
    }
    XmssValidation::height(height);
    if (starting_index == std::numeric_limits<size_t>::max()) {
        throw std::invalid_argument("XMSS pool starting index is exhausted");
    }
    if (pool_size > MAX_POOL_SIZE) {
        throw std::invalid_argument("XMSS pool size exceeds the supported limit");
    }

    _base_seed = base_seed;
    // No lock needed: the instance is not observable by another thread yet.
    try {
        fillCache();
    } catch (...) {
        drainCache();
        qrllib::secure_memory::wipe(_base_seed);
        throw;
    }
}

XmssPool::~XmssPool()
{
    // The async builders capture this object and read _base_seed. They must
    // finish before that seed is erased.
    drainCache();
    qrllib::secure_memory::wipe(_base_seed);
}

void XmssPool::drainCache() noexcept
{
    for (auto& pending : _cache) {
        if (pending.valid()) {
            try {
                pending.wait();
            } catch (...) {
                // Destruction must still continue to the seed wipe. A valid
                // async future normally reports task failures from get(), but
                // wait() may also report an implementation-level future error.
            }
        }
    }
    _cache.clear();
}

void XmssPool::fillCache() {
    const auto maximum = std::numeric_limits<size_t>::max();
    const auto available = maximum - _current_index;
    const auto target_size = std::min(_pool_size, available);

    while (_cache.size() < target_size) {
        const size_t i = _current_index + _cache.size();
        _cache.push_back(std::async(std::launch::async, [this](size_t idx) {
            return prepareTree(idx);
        }, i));
    }
}

std::shared_ptr<XmssFast> XmssPool::getNextTree() {
    std::future<std::shared_ptr<XmssFast>> pending;
    size_t index = 0;
    bool cache_missed = false;

    {
        std::lock_guard<std::mutex> lock(_mutex);

        if (_current_index == std::numeric_limits<size_t>::max()) {
            throw std::overflow_error("XMSS pool tree index is exhausted");
        }

        if (_cache.empty()) {
            // Claim the index under the lock; build the tree outside it.
            index = _current_index++;
            cache_missed = true;
        } else {
            // Move the future out so that the wait below happens outside the
            // critical section. Leaving it in the deque and calling get() here
            // would both serialise every caller behind key generation and allow
            // a second caller to get() an already-consumed future.
            pending = std::move(_cache.front());
            _cache.pop_front();
            _current_index++;

            fillCache();
        }
    }

    if (cache_missed) {
        return prepareTree(index);
    }

    return pending.get();
}

bool XmssPool::isAvailable() {
    std::lock_guard<std::mutex> lock(_mutex);

    // front() is undefined on an empty deque, and _cache is always empty when
    // _pool_size is 0.
    if (_cache.empty()) {
        return false;
    }

    return _cache.front().wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}

std::shared_ptr<XmssFast> XmssPool::prepareTree(size_t index) {
    // Preserve the established pool derivation: append the 1-based index in
    // minimal little-endian form, then derive the 48-byte XMSS seed with
    // SHAKE256. Reserve the exact buffer size before writing the index.
    size_t encoded_index_size = 0;
    for (size_t value = index + 1; value != 0; value >>= 8) {
        ++encoded_index_size;
    }
    std::vector<uint8_t> tmp_seed(_base_seed.size() + encoded_index_size, 0);
    qrllib::secure_memory::WipeGuard<uint8_t> tmp_seed_guard(tmp_seed);
    std::copy(_base_seed.begin(), _base_seed.end(), tmp_seed.begin());

    auto idx = index + 1;
    size_t cursor = _base_seed.size();
    while (idx > 0) {
        tmp_seed[cursor++] = static_cast<unsigned char>(idx & 0xFF);
        idx >>= 8;
    }

    auto derived_seed = shake256(XmssValidation::SEED_SIZE, tmp_seed);
    qrllib::secure_memory::WipeGuard<uint8_t> derived_seed_guard(derived_seed);
    return std::make_shared<XmssFast>(derived_seed, _height);
}
