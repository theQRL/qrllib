// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_XMSSTREEPOOL_H
#define QRLLIB_XMSSTREEPOOL_H

#include <vector>
#include <string>
#include <future>
#include <deque>
#include <memory>
#include <mutex>
#include "xmssBase.h"
#include "xmssFast.h"

// TODO: Add a namespace

// Pre-computes XMSS trees on background threads so that getNextTree() can hand
// one over without paying the key-generation cost inline.
//
// Every index is issued exactly once. XMSS is a stateful one-time signature
// scheme, so handing the same index to two callers would let them sign two
// different messages under the same WOTS+ key. All shared state is therefore
// guarded by _mutex, and the public methods below are safe to call concurrently
// on a single instance.
class XmssPool {
public:
    XmssPool(const TSEED &base_seed,
             unsigned char height,
             size_t starting_index,
             size_t pool_size);

    ~XmssPool() = default;

    std::shared_ptr<XmssFast> getNextTree();

    bool isAvailable();

    size_t getCurrentIndex() {
        std::lock_guard<std::mutex> lock(_mutex);
        return _current_index;
    }

private:
    TSEED _base_seed;
    uint8_t _height;
    size_t _current_index;
    size_t _pool_size;
    std::deque<std::future<std::shared_ptr<XmssFast>>> _cache;
    std::mutex _mutex;

    // Caller must hold _mutex.
    void fillCache();

    // Derives a tree from _base_seed and _height, both immutable after
    // construction, so this is safe to call concurrently and without the lock.
    std::shared_ptr<XmssFast> prepareTree(size_t index);
};

#endif // QRLLIB_XMSSTREEPOOL_H
