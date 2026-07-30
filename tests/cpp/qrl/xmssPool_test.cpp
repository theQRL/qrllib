// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <xmss-alt/algsxmss.h>
#include <xmssBasic.h>
#include <atomic>
#include <iostream>
#include <set>
#include <thread>
#include <vector>
#include "gtest/gtest.h"
#include <misc.h>
#include <xmssPool.h>

namespace {
    std::vector<std::string> pks =
            {
                    "0103002dcc3803df4475334b29eaa2516d1a9b36bc19eed0542cfbb501bf8de95d939b25510d9876c7845b4694441bdc0e2be51f3d3f87f0c7775893845f25d49f9ef1",
                    "010300be9caeafe11fa52edf722063c18616d6d0c6c30dba3e2c9369a6d9260f76818bc424a1b6db5f26ef01ffa4aac8a08440d6a569bc56180b06f51b6ff6e4cc1b2e",
                    "0103005deb91b1d311ecc8c6954e22f3e140ff3e6c04e40cad50c940e60abba3cf766a5db9f39f58e532bea6765e4530cb581db1d6afbb7c05da3261ca4db21177afc5",
                    "010300ea15c686e7b9691b8bac52ee4d0ed33bd75ec600f55b4476b857858460c2c98390712040a5e03bca7a46715a90270ac2f8db8694ffa943091edb9018fa1dda04",
                    "010300cc9aa42776ce6d286003055b793223002acb42f7e6c27773dabfd54960bb7d9d1dc356395528c65ff6f444aae130176c213718dd5c4a39858ca150031fb2451e"
            };

    TEST(XmssPool, Instantiation) {
        std::vector<unsigned char> baseseed(48, 0);

        const uint32_t height = 6;
        const uint32_t starting_index = 0;
        const uint32_t pool_size = 0;
        std::cout << "\n";

        XmssPool pool(baseseed, height, starting_index, pool_size);

        for(int i = 0; i<5; i++)
        {
            EXPECT_EQ(pool.getCurrentIndex(), i);
            auto xmss = pool.getNextTree();
            EXPECT_EQ(pks[i], bin2hstr(xmss->getPK()));
        }
    }

    TEST(XmssPool, Instantiation2) {
        std::vector<unsigned char> seed(48, 0);

        const uint32_t height = 6;
        const uint32_t starting_epoch = 0;
        const uint32_t pool_size = 5;
        std::cout << "\n";

        XmssPool pool(seed, height, starting_epoch, pool_size);

        for(int i = 0; i<5; i++)
        {
            EXPECT_EQ(pool.getCurrentIndex(), i);
            auto xmss = pool.getNextTree();
            EXPECT_EQ(pks[i], bin2hstr(xmss->getPK()));
        }
    }

    TEST(XmssPool, Instantiation3) {
        std::vector<unsigned char> seed(48, 0);

        const uint32_t height = 6;
        const uint32_t starting_epoch = 1;
        const uint32_t pool_size = 4;
        std::cout << "\n";

        XmssPool pool(seed, height, starting_epoch, pool_size);

        for(int i = 1; i<5; i++)
        {
            EXPECT_EQ(pool.getCurrentIndex(), i);
            auto xmss = pool.getNextTree();
            EXPECT_EQ(pks[i], bin2hstr(xmss->getPK()));
        }
    }

    // isAvailable() used to call _cache.front() with no empty() guard, which is
    // undefined behaviour and crashed in practice. _cache is always empty when
    // pool_size is 0, so this reached a public method with no threads involved.
    TEST(XmssPool, IsAvailableOnEmptyCache) {
        std::vector<unsigned char> seed(48, 0);

        XmssPool pool(seed, 4, 0, 0);

        EXPECT_FALSE(pool.isAvailable());
    }

    TEST(XmssPool, IsAvailableWithPrecomputedTrees) {
        std::vector<unsigned char> seed(48, 0);

        XmssPool pool(seed, 4, 0, 2);
        pool.getNextTree();

        // Drains the cache one tree at a time; isAvailable() must stay callable
        // throughout rather than depending on the cache being non-empty.
        EXPECT_NO_THROW(pool.isAvailable());
    }

    // XMSS is a stateful one-time signature scheme, so an index must never be
    // issued twice: two callers holding the same index can sign two different
    // messages under the same WOTS+ key. Unsynchronised _current_index++ and
    // deque access allowed exactly that.
    void expectEveryIndexIssuedOnce(size_t pool_size) {
        const int thread_count = 8;

        for (int attempt = 0; attempt < 20; attempt++) {
            std::vector<unsigned char> seed(48, 0x42);
            XmssPool pool(seed, 4, 0, pool_size);

            std::vector<std::string> collected(thread_count);
            std::vector<std::thread> threads;
            std::atomic<bool> go(false);

            for (int i = 0; i < thread_count; i++) {
                threads.emplace_back([&pool, &collected, &go, i] {
                    while (!go.load(std::memory_order_acquire)) {
                        std::this_thread::yield();
                    }
                    collected[i] = bin2hstr(pool.getNextTree()->getPK());
                });
            }

            // Release the threads together. Letting them start as they are
            // spawned staggers them enough to hide the race.
            go.store(true, std::memory_order_release);

            for (auto &t : threads) {
                t.join();
            }

            std::set<std::string> distinct(collected.begin(), collected.end());
            ASSERT_EQ(distinct.size(), static_cast<size_t>(thread_count))
                << "duplicate tree issued at pool_size=" << pool_size
                << " on attempt " << attempt;
            ASSERT_EQ(pool.getCurrentIndex(), static_cast<size_t>(thread_count));
        }
    }

    TEST(XmssPool, ConcurrentGetNextTreeIsUniqueWithoutCache) {
        // pool_size 0 exercises the prepareTree(_current_index++) branch, where
        // a lost increment used to hand two threads the same index.
        expectEveryIndexIssuedOnce(0);
    }

    TEST(XmssPool, ConcurrentGetNextTreeIsUniqueWithCache) {
        // pool_size 2 exercises the cached branch, where two threads could
        // get() the same future. That is undefined behaviour, not a duplicate,
        // and it crashed rather than returning.
        expectEveryIndexIssuedOnce(2);
    }
}
