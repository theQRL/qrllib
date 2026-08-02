// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
#include <algorithm>
#include "xmssFast.h"
#include "xmssPool.h"
#include "hashing.h"
#include "misc.h"

XmssPool::XmssPool(const TSEED &base_seed, uint8_t height, const size_t starting_index, size_t pool_size) :
        _base_seed(base_seed),
        _height(height),
        _current_index(starting_index),
        _pool_size(pool_size) {
    // No lock needed: the instance is not observable by another thread yet.
    fillCache();
}

void XmssPool::fillCache() {
    size_t start = _current_index + _cache.size();
    size_t end = _current_index + _pool_size;

    for (size_t i = start; i < end; i++) {
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
    // Domain-separate each tree by appending the 1-based index (little-endian,
    // minimal length) to the base seed and deriving the full 48-byte stake
    // seed with SHAKE256. The previous derivation hashed to a 32-byte SHA-256
    // and duplicated its first 16 bytes, so every stake seed satisfied
    // seed[32..47] == seed[0..15] and carried only 256 bits of entropy.
    // NOTE: this changes the trees derived from a given base seed; anything
    // relying on the old derivation must regenerate its expected values.
    auto tmp_seed(_base_seed);

    auto idx = index + 1;
    while (idx > 0) {
        tmp_seed.push_back(static_cast<unsigned char>(idx & 0xFF));
        idx >>= 8;
    }

    return std::make_shared<XmssFast>(shake256(48, tmp_seed), _height);
}
