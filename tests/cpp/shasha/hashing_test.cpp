// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <shasha.h>
#include <qrl/misc.h>
#include <array>
#include "gtest/gtest.h"

namespace {

    TEST(shasha, sha2_256) {
        const std::string input = "This is a test X";
        std::vector<uint8_t> output_hashed(32);

        sha2_256(output_hashed.data(), (uint8_t *) input.data(), input.size());

        auto input_bin = str2bin(input);
        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);
        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b");
    }
}
