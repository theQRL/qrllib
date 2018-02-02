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
    if (_cache.empty()) {
        return prepareTree(_current_index++);
    }

    auto answer = _cache.front().get();
    _cache.pop_front();
    _current_index++;

    fillCache();

    return answer;
}

bool XmssPool::isAvailable() {
    return _cache.front().wait_for(std::chrono::seconds(0)) == std::future_status::ready;
}

std::shared_ptr<XmssFast> XmssPool::prepareTree(size_t index) {
    auto tmp_seed(_base_seed);

    // FIXME: Check with Leon. The commented code is a proposal
//    index++;
//    while(index>0)
//    {
//        tmp_seed.push_back(static_cast<unsigned char &&>(index & 0xFF));
//        index >>= 8;
//    }
//    auto stake_seed = shake256(48, tmp_seed);

    // This was the original approach in python
    auto seed_str = bin2hstr(_base_seed) + std::to_string(index + 1);
    auto stake_seed = sha2_256(str2bin(seed_str));
    stake_seed.reserve(48);
    std::copy_n(stake_seed.begin(), 16, std::back_inserter(stake_seed));

    return std::make_shared<XmssFast>(stake_seed, _height);
}
