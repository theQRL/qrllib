// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"

#include <dilithium/ref/api.h>
#include <dilithium/ref/randombytes.h>

namespace {
    TEST(DilithumReferenceTest, sign_keypair) {
        std::vector<unsigned char> message(100);

        std::vector<unsigned char> pk(CRYPTO_PUBLICKEYBYTES);
        std::vector<unsigned char> sk(CRYPTO_SECRETKEYBYTES);

        std::vector<unsigned char> message_signed(message.size() + CRYPTO_BYTES);
        std::vector<unsigned char> message2(message.size() + CRYPTO_BYTES);

        // Generate a random message
        randombytes(message.data(), message.size());

        // Generate random public/secret keys
        crypto_sign_keypair(pk.data(), sk.data());

        // Sign message
        unsigned long long message_signed_size_dummy;
        crypto_sign(message_signed.data(),
                    &message_signed_size_dummy,
                    message.data(),
                    message.size(),
                    sk.data());

        EXPECT_EQ(message_signed_size_dummy, message_signed.size());

        // Sign open
        unsigned long long message2_size_dummy;
        crypto_sign_open(message2.data(),
                         &message2_size_dummy,
                         message_signed.data(),
                         message_signed.size(),
                         pk.data());


        for (int i = 0; i < message.size(); i++) {
            EXPECT_EQ(message[i], message2[i]);
        }
    }
}
