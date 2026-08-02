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
    // Regenerated 2026-08-02: prepareTree now derives the full 48-byte stake
    // seed with shake256(base_seed || index+1) instead of duplicating the
    // first 16 bytes of a sha2_256 digest.
    std::vector<std::string> pks =
            {
                    "0103002cdddec48985cc9acd9d970781782a1c5f1000ee464370b79a8639dc669defb803eb90b52a39a2be669053476fa1bb3eb8d9514c432eb9bd1e4a78b36d271d7e",
                    "010300e76e8a65bd7df657e91b95a9895baebbca7f003e3ab8ae6e7bcf6edc0d48f212551a7d78a5df848aa9808f39e669817362e0870178c1a70c1e835b6daa0b3d91",
                    "01030087eb6f611bd88cf08f7948995216661e01fce87f9dcff14d58858e8770422c69691d6ce737e816c44bc21e8e7e422e8068af1d8bfb89a05db98e822178352d63",
                    "010300e3d66e891f02bff7dcb2d87fe7126e549e0e993b6a459992fc5fcc4b752eeb4ab2428e3e0280b7da7c82db6c135ab615cddd08412246580eee32e9c692eaa318",
                    "010300eceed296a8f2b3a25af19cfc90d3c2725a0c6b9aa263523eb9a6bd5155e80326384349175d2c5aeeeb5032b67d19150a9bb68ee43f0a58000aa7e6b2dc88d2cd"
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
