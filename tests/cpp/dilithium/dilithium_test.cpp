// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include "../../../src/dilithium/dilithium.h"

namespace {
    TEST(DilithumTest, sign_keypair) {
        std::vector<unsigned char> message{0, 1, 2, 4, 6, 9, 1};

        Dilithium dilithium;

        auto message_signed = dilithium.sign(message);

        std::vector<unsigned char> message_out(message.size());
        auto pk = dilithium.getPK();

        auto ret = Dilithium::sign_open(message_out, message_signed, pk);

        EXPECT_TRUE(ret);
    }

    TEST(DilithumTest, sign_keypair_fail) {
        std::vector<unsigned char> message{0, 1, 2, 4, 6, 9, 1};

        Dilithium dilithium;

        auto message_signed = dilithium.sign(message);

        std::vector<unsigned char> message_out(message.size());
        auto pk = dilithium.getPK();

        message_signed[3] ^= 1;

        auto ret = Dilithium::sign_open(message_out, message_signed, pk);

        EXPECT_FALSE(ret);
    }

}
