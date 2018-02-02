// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include <kyber/kyber.h>

namespace {
    TEST(KyberTest, basic_key_exchange) {
        Kyber alice;
        Kyber bob;

        // Alice sends her public key to Bob
        auto alicePublicKey = alice.getPK();

        // Bob receives the public key, derives a secret and a response
        bob.kem_encode(alicePublicKey);
        auto cypherText = bob.getCypherText();

        // Bob sends the cyphertext to Alice
        auto valid = alice.kem_decode(cypherText);
        EXPECT_TRUE(valid);

        // Now Alice and Bob share the same key
        auto aliceKey = alice.getMyKey();
        auto bobKey = bob.getMyKey();

        for (int i = 0; i < aliceKey.size(); i++) {
            EXPECT_EQ(aliceKey[i], bobKey[i]);
        }
    }
}
