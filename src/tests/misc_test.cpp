// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"

#include <misc.h>
#include "word_list.h"

namespace {
#define XMSS_HEIGHT 8

    TEST(MISC, vec2hex) {
        std::vector<unsigned char> data;

        data.push_back(1);
        data.push_back(2);

        EXPECT_EQ(data.size(), 2);
        EXPECT_EQ(bin2hstr(data, 4), "0102");

        auto data_long = std::vector<unsigned char>({0, 1, 2, 3, 4, 6, 7, 8});
        EXPECT_EQ(data_long.size(), 8);
        EXPECT_EQ(bin2hstr(data_long, 4), "00010203\n04060708");
        EXPECT_EQ(bin2hstr(data_long, 8), "0001020304060708");
    }

    TEST(MISC, shake128) {
        const std::string input = "This is a test X";
        const size_t hash_size = 32;

        auto input_bin = str2bin(input);
        auto output_hashed = shake128(hash_size, input_bin);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "02c7654fd239753b787067b1b75523d9bd2c39daa384e4b0d4f91eb78d2a5492");
    }

    TEST(MISC, shake256) {
        const std::string input = "This is a test X";
        const size_t hash_size = 32;

        auto input_bin = str2bin(input);
        auto output_hashed = shake256(hash_size, input_bin);

        EXPECT_EQ(input_bin.size(), 16);
        EXPECT_EQ(output_hashed.size(), 32);

        EXPECT_EQ(bin2hstr(input_bin), "54686973206973206120746573742058");
        EXPECT_EQ(bin2hstr(output_hashed), "b3453cb0cbd37d726a842eb750e6091b15a92efd2695e3191a96d8d07413db04");
    }

    TEST(MISC, bin2mnemonic_empty) {
        std::vector<unsigned char> input = {};

        auto mnemonic = bin2mnemonic(input, wordList);
        EXPECT_EQ(mnemonic, "");
    }

    TEST(MISC, bin2mnemonic_simple1) {
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78};

        auto mnemonic = bin2mnemonic(input, wordList);
        EXPECT_EQ(mnemonic, "basin eighth khaki");
    }

    TEST(MISC, bin2mnemonic_simple2) {
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78, 0x00};

        auto mnemonic = bin2mnemonic(input, wordList);
        EXPECT_EQ(mnemonic, "basin eighth khaki aback");
    }

    TEST(MISC, bin2mnemonic_simple3) {
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78, 0x01};

        auto mnemonic = bin2mnemonic(input, wordList);
        EXPECT_EQ(mnemonic, "basin eighth khaki bag");
    }

    TEST(MISC, bin2mnemonic_simple3b) {
        // FIXME: This could be a problem
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78, 0x01, 0x00};

        auto mnemonic = bin2mnemonic(input, wordList);
        EXPECT_EQ(mnemonic, "basin eighth khaki bag");
    }

    TEST(MISC, bin2mnemonic_simple4) {
        std::vector<unsigned char> input = {0x00};

        auto mnemonic = bin2mnemonic(input, wordList);
        EXPECT_EQ(mnemonic, "aback");
    }

    TEST(MISC, bin2mnemonic_simple5) {
        std::vector<unsigned char> input = {0x01};

        auto mnemonic = bin2mnemonic(input, wordList);
        EXPECT_EQ(mnemonic, "absurd");
    }

    TEST(MISC, mnemonic2bin_simple1) {
        std::string input = "basin eighth khaki aback";
        auto data = mnemonic2bin(input, wordList);
        EXPECT_EQ(bin2hstr(data), "123456780000");
    }

    TEST(MISC, mnemonic2bin_simple2) {
        std::string input = "basin eighth khaki bag";
        auto data = mnemonic2bin(input, wordList);

        EXPECT_EQ(bin2hstr(data), "123456780100");
    }

    TEST(MISC, mnemonic2bin_long) {
        std::string input = "law bruise screen lunar than loft but franc strike asleep dwarf tavern dragon alarm "
                            "snack queen meadow thing far cotton add emblem strive probe zurich edge peer alight "
                            "libel won corn medal";

        auto data = mnemonic2bin(input, wordList);

        EXPECT_EQ( bin2hstr(data),
                   "7bf1e7c1c84be2c820211572d990c0430e09401053ce2af489ee3e4d030c027464d9cac1fff449a2405b7f3fc63018a4");
    }

    TEST(MISC, mnemonic2bin_wrongword) {
        EXPECT_THROW({
                         std::string input = "basin xxWRONGxx";
                         auto data = mnemonic2bin(input, wordList);
                     },
                     std::invalid_argument);
    }

}
