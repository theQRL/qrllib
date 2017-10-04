// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <algsxmss.h>
#include <xmss.h>
#include <vector>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>
#include <xmssPool.h>

namespace {
    TEST(XmssPool, Instantiation) {
        std::vector<unsigned char> baseseed(48, 0);

        const uint32_t height = 6;
        const uint32_t starting_index = 0;
        const uint32_t pool_size = 0;
        std::cout << "\n";

        XmssPool pool(baseseed, height, starting_index, pool_size);

        std::vector<std::string> pks =
                {
                    "2cdddec48985cc9acd9d970781782a1c5f1000ee464370b79a8639dc669defb803eb90b52a39a2be669053476fa1bb3eb8d9514c432eb9bd1e4a78b36d271d7e",
                    "e76e8a65bd7df657e91b95a9895baebbca7f003e3ab8ae6e7bcf6edc0d48f212551a7d78a5df848aa9808f39e669817362e0870178c1a70c1e835b6daa0b3d91",
                    "87eb6f611bd88cf08f7948995216661e01fce87f9dcff14d58858e8770422c69691d6ce737e816c44bc21e8e7e422e8068af1d8bfb89a05db98e822178352d63",
                    "e3d66e891f02bff7dcb2d87fe7126e549e0e993b6a459992fc5fcc4b752eeb4ab2428e3e0280b7da7c82db6c135ab615cddd08412246580eee32e9c692eaa318",
                    "eceed296a8f2b3a25af19cfc90d3c2725a0c6b9aa263523eb9a6bd5155e80326384349175d2c5aeeeb5032b67d19150a9bb68ee43f0a58000aa7e6b2dc88d2cd"
                };

        for(int i = 0; i<5; i++)
        {
            EXPECT_EQ(pool.getCurrentIndex(), i);
            auto xmss = pool.getNextTree();
            EXPECT_EQ(pks[i], bin2hstr(xmss.getPK()));
        }
    }

    TEST(XmssPool, Instantiation2) {
        std::vector<unsigned char> seed(48, 0);

        const uint32_t height = 6;
        const uint32_t starting_epoch = 0;
        const uint32_t pool_size = 5;
        std::cout << "\n";

        XmssPool pool(seed, height, starting_epoch, pool_size);

        std::vector<std::string> pks =
                {
                        "2cdddec48985cc9acd9d970781782a1c5f1000ee464370b79a8639dc669defb803eb90b52a39a2be669053476fa1bb3eb8d9514c432eb9bd1e4a78b36d271d7e",
                        "e76e8a65bd7df657e91b95a9895baebbca7f003e3ab8ae6e7bcf6edc0d48f212551a7d78a5df848aa9808f39e669817362e0870178c1a70c1e835b6daa0b3d91",
                        "87eb6f611bd88cf08f7948995216661e01fce87f9dcff14d58858e8770422c69691d6ce737e816c44bc21e8e7e422e8068af1d8bfb89a05db98e822178352d63",
                        "e3d66e891f02bff7dcb2d87fe7126e549e0e993b6a459992fc5fcc4b752eeb4ab2428e3e0280b7da7c82db6c135ab615cddd08412246580eee32e9c692eaa318",
                        "eceed296a8f2b3a25af19cfc90d3c2725a0c6b9aa263523eb9a6bd5155e80326384349175d2c5aeeeb5032b67d19150a9bb68ee43f0a58000aa7e6b2dc88d2cd"
                };

        for(int i = 0; i<5; i++)
        {
            EXPECT_EQ(pool.getCurrentIndex(), i);
            auto xmss = pool.getNextTree();
            EXPECT_EQ(pks[i], bin2hstr(xmss.getPK()));
        }
    }

    TEST(XmssPool, Instantiation3) {
        std::vector<unsigned char> seed(48, 0);

        const uint32_t height = 6;
        const uint32_t starting_epoch = 1;
        const uint32_t pool_size = 4;
        std::cout << "\n";

        XmssPool pool(seed, height, starting_epoch, pool_size);

        std::vector<std::string> pks =
                {
                        "2cdddec48985cc9acd9d970781782a1c5f1000ee464370b79a8639dc669defb803eb90b52a39a2be669053476fa1bb3eb8d9514c432eb9bd1e4a78b36d271d7e",
                        "e76e8a65bd7df657e91b95a9895baebbca7f003e3ab8ae6e7bcf6edc0d48f212551a7d78a5df848aa9808f39e669817362e0870178c1a70c1e835b6daa0b3d91",
                        "87eb6f611bd88cf08f7948995216661e01fce87f9dcff14d58858e8770422c69691d6ce737e816c44bc21e8e7e422e8068af1d8bfb89a05db98e822178352d63",
                        "e3d66e891f02bff7dcb2d87fe7126e549e0e993b6a459992fc5fcc4b752eeb4ab2428e3e0280b7da7c82db6c135ab615cddd08412246580eee32e9c692eaa318",
                        "eceed296a8f2b3a25af19cfc90d3c2725a0c6b9aa263523eb9a6bd5155e80326384349175d2c5aeeeb5032b67d19150a9bb68ee43f0a58000aa7e6b2dc88d2cd"
                };

        for(int i = 1; i<5; i++)
        {
            EXPECT_EQ(pool.getCurrentIndex(), i);
            auto xmss = pool.getNextTree();
            EXPECT_EQ(pks[i], bin2hstr(xmss.getPK()));
        }
    }
}
