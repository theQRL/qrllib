// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include <kyber/kyber.h>

#include <array>
#include <stdexcept>
#include <utility>

namespace {
    class MutableKyber : public Kyber {
    public:
        void replaceSecretKey(const std::vector<uint8_t> &sk) {
            _sk = sk;
        }
    };

    TEST(KyberTest, basic_key_exchange) {
        Kyber alice;
        Kyber bob;

        // Alice sends her public key to Bob
        auto alicePublicKey = alice.getPK();

        // Bob receives the public key, derives a secret and a response
        ASSERT_TRUE(bob.kem_encode(alicePublicKey));
        auto cypherText = bob.getCypherText();
        EXPECT_EQ(static_cast<size_t>(KYBER_CIPHERTEXTBYTES), cypherText.size());

        // Bob sends the cyphertext to Alice
        auto valid = alice.kem_decode(cypherText);
        EXPECT_TRUE(valid);

        // Now Alice and Bob share the same key
        auto aliceKey = alice.getMyKey();
        auto bobKey = bob.getMyKey();

        EXPECT_EQ(static_cast<size_t>(KYBER_SYMBYTES), aliceKey.size());
        EXPECT_EQ(bobKey, aliceKey);
    }

    TEST(KyberTest, imported_keys_require_exact_sizes) {
        Kyber generated;
        const auto pk = generated.getPK();
        const auto sk = generated.getSK();

        EXPECT_NO_THROW(Kyber(pk, sk));

        for (const auto size : std::array<size_t, 3>{0, KYBER_PUBLICKEYBYTES - 1,
                                                     KYBER_PUBLICKEYBYTES + 1}) {
            auto invalid_pk = pk;
            invalid_pk.resize(size);
            EXPECT_THROW(Kyber(invalid_pk, sk), std::invalid_argument);
        }

        for (const auto size : std::array<size_t, 3>{0, KYBER_SECRETKEYBYTES - 1,
                                                     KYBER_SECRETKEYBYTES + 1}) {
            auto invalid_sk = sk;
            invalid_sk.resize(size);
            EXPECT_THROW(Kyber(pk, invalid_sk), std::invalid_argument);
        }
    }

    TEST(KyberTest, copy_and_assignment_preserve_complete_state) {
        Kyber recipient;
        Kyber source;
        ASSERT_TRUE(source.kem_encode(recipient.getPK()));

        Kyber copied(source);
        Kyber assigned;
        assigned = source;

        EXPECT_EQ(source.getPK(), copied.getPK());
        EXPECT_EQ(source.getSK(), copied.getSK());
        EXPECT_EQ(source.getMyKey(), copied.getMyKey());
        EXPECT_EQ(source.getCypherText(), copied.getCypherText());
        EXPECT_EQ(source.getPK(), assigned.getPK());
        EXPECT_EQ(source.getSK(), assigned.getSK());
        EXPECT_EQ(source.getMyKey(), assigned.getMyKey());
        EXPECT_EQ(source.getCypherText(), assigned.getCypherText());

        assigned = assigned;
        assigned = std::move(assigned);
        EXPECT_EQ(source.getMyKey(), assigned.getMyKey());
        EXPECT_EQ(source.getCypherText(), assigned.getCypherText());
    }

    TEST(KyberTest, encapsulation_requires_exact_peer_key_and_clears_outputs) {
        Kyber recipient;
        Kyber sender;
        const auto peer_pk = recipient.getPK();

        for (const auto size : std::array<size_t, 3>{0, KYBER_PUBLICKEYBYTES - 1,
                                                     KYBER_PUBLICKEYBYTES + 1}) {
            ASSERT_TRUE(sender.kem_encode(peer_pk));
            ASSERT_EQ(static_cast<size_t>(KYBER_SYMBYTES), sender.getMyKey().size());
            ASSERT_EQ(static_cast<size_t>(KYBER_CIPHERTEXTBYTES),
                      sender.getCypherText().size());

            auto invalid_pk = peer_pk;
            invalid_pk.resize(size);
            EXPECT_FALSE(sender.kem_encode(invalid_pk));
            EXPECT_TRUE(sender.getMyKey().empty());
            EXPECT_TRUE(sender.getCypherText().empty());
        }
    }

    TEST(KyberTest, decapsulation_requires_exact_ciphertext_and_clears_prior_key) {
        Kyber recipient;
        Kyber sender;
        ASSERT_TRUE(sender.kem_encode(recipient.getPK()));
        const auto ciphertext = sender.getCypherText();

        for (const auto size : std::array<size_t, 3>{0, KYBER_CIPHERTEXTBYTES - 1,
                                                     KYBER_CIPHERTEXTBYTES + 1}) {
            ASSERT_TRUE(recipient.kem_decode(ciphertext));
            ASSERT_EQ(static_cast<size_t>(KYBER_SYMBYTES), recipient.getMyKey().size());

            auto invalid_ciphertext = ciphertext;
            invalid_ciphertext.resize(size);
            EXPECT_FALSE(recipient.kem_decode(invalid_ciphertext));
            EXPECT_TRUE(recipient.getMyKey().empty());
        }
    }

    TEST(KyberTest, well_sized_rejection_publishes_fresh_implicit_rejection_key) {
        Kyber recipient;
        Kyber sender;
        ASSERT_TRUE(sender.kem_encode(recipient.getPK()));
        auto ciphertext = sender.getCypherText();
        ASSERT_TRUE(recipient.kem_decode(ciphertext));
        const auto accepted_key = recipient.getMyKey();

        ciphertext[0] ^= 1;
        EXPECT_FALSE(recipient.kem_decode(ciphertext));
        EXPECT_EQ(static_cast<size_t>(KYBER_SYMBYTES), recipient.getMyKey().size());
        EXPECT_NE(accepted_key, recipient.getMyKey());
    }

    TEST(KyberTest, decapsulation_revalidates_protected_secret_key) {
        MutableKyber recipient;
        Kyber sender;
        ASSERT_TRUE(sender.kem_encode(recipient.getPK()));
        const auto ciphertext = sender.getCypherText();
        const auto sk = recipient.getSK();

        for (const auto size : std::array<size_t, 3>{0, KYBER_SECRETKEYBYTES - 1,
                                                     KYBER_SECRETKEYBYTES + 1}) {
            ASSERT_TRUE(recipient.kem_decode(ciphertext));
            auto invalid_sk = sk;
            invalid_sk.resize(size);
            recipient.replaceSecretKey(invalid_sk);
            EXPECT_FALSE(recipient.kem_decode(ciphertext));
            EXPECT_TRUE(recipient.getMyKey().empty());
            recipient.replaceSecretKey(sk);
        }
    }
}
