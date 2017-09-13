// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <algsxmss.h>
#include <xmss.h>
#include <vector>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>

namespace {
#define XMSS_HEIGHT 8

    TEST(MISC, vec2hex) {
        std::vector<unsigned char> data;

        data.push_back(1);
        data.push_back(2);

        EXPECT_EQ(data.size(), 2);
        EXPECT_EQ(vec2hexstr(data, 4), "0102");

        auto data_long = std::vector<unsigned char>({0, 1, 2, 3, 4, 6, 7, 8});
        EXPECT_EQ(data_long.size(), 8);
        EXPECT_EQ(vec2hexstr(data_long, 4), "00010203\n04060708");
        EXPECT_EQ(vec2hexstr(data_long, 8), "0001020304060708");
    }

    TEST(MISC, shake128) {
        const std::string input = "This is a test X";
        const size_t hash_size = 32;

        auto input_bin = str2bin(input);
        auto output_hashed = shake128(hash_size, input_bin);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(vec2hexstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(vec2hexstr(output_hashed), "02c7654fd239753b787067b1b75523d9bd2c39daa384e4b0d4f91eb78d2a5492");
    }

    TEST(MISC, shake256) {
        const std::string input = "This is a test X";
        const size_t hash_size = 32;

        auto input_bin = str2bin(input);
        auto output_hashed = shake256(hash_size, input_bin);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(vec2hexstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(vec2hexstr(output_hashed), "b3453cb0cbd37d726a842eb750e6091b15a92efd2695e3191a96d8d07413db04");
    }



}
