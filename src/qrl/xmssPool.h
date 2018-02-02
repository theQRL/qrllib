// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_XMSSTREEPOOL_H
#define QRLLIB_XMSSTREEPOOL_H

#include <vector>
#include <string>
#include <future>
#include <deque>
#include <memory>
#include "xmssBase.h"
#include "xmssFast.h"

// TODO: Add a namespace
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
        return _current_index;
    }

private:
    TSEED _base_seed;
    uint8_t _height;
    size_t _current_index;
    size_t _pool_size;
    std::deque<std::future<std::shared_ptr<XmssFast>>> _cache;

    void fillCache();

    std::shared_ptr<XmssFast> prepareTree(size_t index);
};

#endif // QRLLIB_XMSSTREEPOOL_H
