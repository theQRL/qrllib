// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <hashing.h>
#include <misc.h>
#include "gtest/gtest.h"

namespace {

    TEST(Hashing, sha2_256) {
        const std::string input = "This is a test X";

        auto input_bin = str2bin(input);
        auto output_hashed = sha2_256(input_bin);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b");
    }

    TEST(Hashing, sha2_256_1) {
        const std::string input = "This is a test X";

        auto input_bin = str2bin(input);
        auto output_hashed = sha2_256_n(input_bin, 1);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b");
    }

    TEST(Hashing, sha2_256_n) {
        const std::string input = "This is a test X";

        auto input_bin = str2bin(input);
        auto output_hashed = sha2_256_n(input_bin, 16);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "3be2d7e048d22de2c117465e5b4b819e764352680027c9790a53a7326d62a0fe");
    }

    TEST(Hashing, shake128) {
        const std::string input = "This is a test X";
        const size_t hash_size = 32;

        auto input_bin = str2bin(input);
        auto output_hashed = shake128(hash_size, input_bin);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "02c7654fd239753b787067b1b75523d9bd2c39daa384e4b0d4f91eb78d2a5492");
    }

    TEST(Hashing, shake256) {
        const std::string input = "This is a test X";
        const size_t hash_size = 32;

        auto input_bin = str2bin(input);
        auto output_hashed = shake256(hash_size, input_bin);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "b3453cb0cbd37d726a842eb750e6091b15a92efd2695e3191a96d8d07413db04");
    }
}
