// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"

#include <misc.h>
#include <hashing.h>

namespace {
#define XMSS_HEIGHT 8

    TEST(Misc, bin2hstr) {
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

    TEST(Misc, hstr2bin) {
        EXPECT_EQ(hstr2bin("10"), std::vector<unsigned char>({0x10}));
        EXPECT_EQ(hstr2bin("102aAB"), std::vector<unsigned char>({0x10, 0x2a, 0xab}));
    }


    TEST(Misc, bin2mnemonic_empty) {
        std::vector<unsigned char> input = {};

        auto mnemonic = bin2mnemonic(input);
        EXPECT_EQ(mnemonic, "");
    }

    TEST(Misc, bin2mnemonic_3_bytes) {
        std::vector<unsigned char> input = {0x00, 0x00, 0x00};

        auto mnemonic = bin2mnemonic(input);
        EXPECT_EQ(mnemonic, "aback aback");
    }

    TEST(Misc, bin2mnemonic_3_bytes_b) {
        std::vector<unsigned char> input = {0x00, 0x01, 0x00};

        auto mnemonic = bin2mnemonic(input);
        EXPECT_EQ(mnemonic, "aback badge");
    }

    TEST(Misc, bin2mnemonic_3_bytes_c) {
        std::vector<unsigned char> input = {0x00, 0x02, 0x00};

        auto mnemonic = bin2mnemonic(input);
        EXPECT_EQ(mnemonic, "aback bunny");
    }

    TEST(Misc, bin2mnemonic_4_bytes_a) {
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78};

        EXPECT_THROW(bin2mnemonic(input), std::invalid_argument);
    }

    TEST(Misc, bin2mnemonic_5_bytes_b) {
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78, 0x00};
        EXPECT_THROW(bin2mnemonic(input), std::invalid_argument);
    }

    TEST(Misc, bin2mnemonic_6_bytes_a) {
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78, 0x01, 0x00};

        auto mnemonic = bin2mnemonic(input);
        EXPECT_EQ(mnemonic, "base elbow knew badge");
    }

    TEST(Misc, bin2mnemonic_6_bytes_b) {
        std::vector<unsigned char> input = {0x12, 0x34, 0x56, 0x78, 0x01, 0x09};

        auto mnemonic = bin2mnemonic(input);
        EXPECT_EQ(mnemonic, "base elbow knew bald");
    }

    TEST(Misc, mnemonic2bin_simple1) {
        std::string input = "base elbow knew aback bag bunny";
        auto data = mnemonic2bin(input);
        EXPECT_EQ(bin2hstr(data), "123456780000102200");
    }

    TEST(Misc, mnemonic2bin_simple2) {
        std::string input = "base elbow knew bag";
        auto data = mnemonic2bin(input);

        EXPECT_EQ(bin2hstr(data), "123456780102");
    }

    TEST(Misc, mnemonic2bin_unknown) {
        std::string input = "base elbow knew unknown";
        EXPECT_THROW(mnemonic2bin(input), std::invalid_argument);
    }


    TEST(Misc, mnemonic2bin_long) {
        std::string input = "law bruise screen lunar than loft but franc strike asleep dwarf tavern dragon alarm "
                "snack queen meadow thing far cotton add emblem strive probe zurich edge peer alight "
                "libel won corn medal";

        auto data = mnemonic2bin(input);

        EXPECT_EQ(bin2hstr(data),
                  "7ad1e6c1083de2081221056dd8b0c142cdfa3fd053cd4ae288ee324cd30e027462d8eaaffff445a1105b7e4fc1302894");
    }

    TEST(Misc, mnemonic2bin_wrongword) {
        EXPECT_THROW({
                         std::string input = "basin xxWRONGxx";
                         auto data = mnemonic2bin(input);
                     },
                     std::invalid_argument);
    }

    TEST(Misc, getHashChainSeed) {
        const std::string input = "This is a test X";
        auto input_bin = str2bin(input);
        auto initial_seed = shake256(32, input_bin);

        auto r = getHashChainSeed(initial_seed, 10, 10);
        EXPECT_EQ(r.size(), 10);

        EXPECT_EQ(bin2hstr(r[0]), "51971ec39522177c33a60b915fbf8fb21570018444fbe63692b13438fdceaad0");
        EXPECT_EQ(bin2hstr(r[1]), "9920072f88d306b4a6ac7089ce9917987e39c78945cce698ed94f709c733dc06");
        EXPECT_EQ(bin2hstr(r[2]), "c328fcaceec93d7154f4bdca0e47a7879ab818155f21408c5b102e08bbb025ca");
        EXPECT_EQ(bin2hstr(r[3]), "75fe0b40f93d78f8de2fd133c03ab54fb03c2d3ddd79902e21107ad46430012b");
        EXPECT_EQ(bin2hstr(r[4]), "e8f521172ac2539f298d31338135d7095fd0c6893757ec4b6a3ae466c234f3ad");
        EXPECT_EQ(bin2hstr(r[5]), "3711e7b57f9c6f5260f94f0d6f6c0f8d7058e1178e33fa66ffb44c59f80b2fbd");
        EXPECT_EQ(bin2hstr(r[6]), "159acf444f864cceebf45af42aa10d9045f022e5cad53937d8fcfe448430f02d");
        EXPECT_EQ(bin2hstr(r[7]), "def097a0ba2de30f98f88188de84b0f6db41e70dbde8e6d93b4ec6afa6fa319c");
        EXPECT_EQ(bin2hstr(r[8]), "ab10d7e3a6c6a782143d864606a4cd6f70147c7c203528b2af2dbd409dde0f02");
        EXPECT_EQ(bin2hstr(r[9]), "a1083ac97a92ba4a86a37f09a018e5ef1db29e80e007224effdd8bbcafe7445b");
    }

}
