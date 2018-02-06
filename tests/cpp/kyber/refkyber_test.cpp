// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include <kyber/ref/api.h>

namespace {
    TEST(KyberReferenceTest, decode) {
        // Verify constants for 768
        EXPECT_EQ(1088, KYBER_PUBLICKEYBYTES);
        EXPECT_EQ(1152, KYBER_CIPHERTEXTBYTES);
        EXPECT_EQ(2400, KYBER_SECRETKEYBYTES);

        // Based on reference implementation
        std::vector<uint8_t> key_a(KYBER_SYMBYTES, 0);
        std::vector<uint8_t> send_b(KYBER_CIPHERTEXTBYTES, 0);
        std::vector<uint8_t> sk_a(KYBER_SECRETKEYBYTES, 0);

        std::vector<uint8_t> expected_key_a = {
                160, 158, 123, 88, 195, 221, 144, 132,
                239, 112, 79, 27, 129, 240, 212, 8,
                26, 81, 138, 214, 114, 135, 124, 174,
                183, 114, 186, 220, 103, 23, 227, 88
        };

        //Alice uses Bobs response to get her secret key
        crypto_kem_dec(key_a.data(), send_b.data(), sk_a.data());

        for (int i = 0; i < KYBER_SYMBYTES; i++) {
            EXPECT_EQ(expected_key_a[i], key_a[i]);
        }
    }

    TEST(KyberReferenceTest, encode_decode) {
        // Verify constants for 768
        EXPECT_EQ(1088, KYBER_PUBLICKEYBYTES);
        EXPECT_EQ(1152, KYBER_CIPHERTEXTBYTES);
        EXPECT_EQ(2400, KYBER_SECRETKEYBYTES);

        // Based on reference implementation
        std::vector<uint8_t> pk(KYBER_PUBLICKEYBYTES, 0);
        std::vector<uint8_t> sk_a(KYBER_SECRETKEYBYTES, 0);

        std::vector<uint8_t> key_a(KYBER_SYMBYTES);
        std::vector<uint8_t> key_b(KYBER_SYMBYTES);
        std::vector<uint8_t> send_b(KYBER_CIPHERTEXTBYTES);

        //Alice generates a public key
        crypto_kem_keypair(pk.data(), sk_a.data());

        //Bob derives a secret key and creates a response
        crypto_kem_enc(send_b.data(),
                       key_b.data(),
                       pk.data());

        //Alice uses Bobs response to get her secret key
        auto validation_error = crypto_kem_dec(key_a.data(),
                                               send_b.data(),
                                               sk_a.data());

        EXPECT_EQ(0, validation_error);

        if (!validation_error) {
            for (int i = 0; i < KYBER_SYMBYTES; i++) {
                EXPECT_EQ(key_a[i], key_b[i]);
            }
        }
    }

    TEST(KyberReferenceTest, original) {
        unsigned char key_a[KYBER_SYMBYTES], key_b[KYBER_SYMBYTES];
        unsigned char pk[KYBER_PUBLICKEYBYTES];
        unsigned char sendb[KYBER_CIPHERTEXTBYTES];
        unsigned char sk_a[KYBER_SECRETKEYBYTES];

        //Alice generates a public key
        crypto_kem_keypair(pk, sk_a);

        //Bob derives a secret key and creates a response
        crypto_kem_enc(sendb, key_b, pk);

        //Alice uses Bobs response to get her secret key
        auto validation_error = crypto_kem_dec(key_a, sendb, sk_a);
        EXPECT_EQ(0, validation_error);

        if (memcmp(key_a, key_b, KYBER_SYMBYTES))
            printf("ERROR keys\n");
    }

}
