// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include <libkyber.h>

namespace {
    TEST(DISABLED_KyberReferenceTest, check_keys) {
        // Based on reference implementation
        std::vector<uint8_t> key_a(KYBER_SYMBYTES);
        std::vector<uint8_t> key_b(KYBER_SYMBYTES);

        std::vector<uint8_t> pk(KYBER_PUBLICKEYBYTES);
        std::vector<uint8_t> send_b(KYBER_CIPHERTEXTBYTES);
        std::vector<uint8_t> sk_a(KYBER_SECRETKEYBYTES);

        //Alice generates a public key
        crypto_kem_keypair(pk.data(), sk_a.data());

        //Bob derives a secret key and creates a response
        crypto_kem_enc(send_b.data(), key_b.data(), pk.data());

        //Alice uses Bobs response to get her secret key
        crypto_kem_dec(key_a.data(), send_b.data(), sk_a.data());

        for(int i = 0; i<key_a.size(); i++)
        {
            EXPECT_EQ(key_a[i], key_b[i]);
        }
    }
}
