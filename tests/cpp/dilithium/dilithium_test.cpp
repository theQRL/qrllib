// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include "../../../src/dilithium/dilithium.h"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

namespace {
    class MutableDilithium : public Dilithium {
    public:
        void replaceSecretKey(const std::vector<uint8_t> &sk) {
            _sk = sk;
        }
    };

    TEST(DilithumTest, sign_keypair) {
        std::vector<unsigned char> message{0, 1, 2, 4, 6, 9, 1};

        Dilithium dilithium;

        auto message_signed = dilithium.sign(message);
        ASSERT_EQ(message.size() + CRYPTO_BYTES, message_signed.size());
        EXPECT_TRUE(std::equal(message.begin(), message.end(),
                               message_signed.end() - message.size()));

        std::vector<unsigned char> message_out(32, 0xa5);
        auto pk = dilithium.getPK();

        auto ret = Dilithium::sign_open(message_out, message_signed, pk);

        EXPECT_TRUE(ret);
        EXPECT_EQ(message, message_out);
        EXPECT_EQ(message, Dilithium::extract_message(message_signed));
        EXPECT_EQ(std::vector<uint8_t>(message_signed.begin(),
                                       message_signed.begin() + CRYPTO_BYTES),
                  Dilithium::extract_signature(message_signed));
    }

    TEST(DilithumTest, sign_keypair_fail) {
        std::vector<unsigned char> message{0, 1, 2, 4, 6, 9, 1};

        Dilithium dilithium;

        auto message_signed = dilithium.sign(message);

        std::vector<unsigned char> message_out(64, 0xa5);
        auto pk = dilithium.getPK();

        message_signed[3] ^= 1;

        auto ret = Dilithium::sign_open(message_out, message_signed, pk);

        EXPECT_FALSE(ret);
        EXPECT_TRUE(message_out.empty());
    }

    TEST(DilithumTest, copy_assignment_and_aliased_open_preserve_behavior) {
        Dilithium original;
        Dilithium copied(original);
        Dilithium assigned;
        assigned = original;

        EXPECT_EQ(original.getPK(), copied.getPK());
        EXPECT_EQ(original.getSK(), copied.getSK());
        EXPECT_EQ(original.getPK(), assigned.getPK());
        EXPECT_EQ(original.getSK(), assigned.getSK());

        assigned = assigned;
        assigned = std::move(assigned);

        const std::vector<uint8_t> message{9, 8, 7, 6};
        auto signed_message = assigned.sign(message);
        const auto pk = assigned.getPK();

        EXPECT_TRUE(Dilithium::sign_open(signed_message, signed_message, pk));
        EXPECT_EQ(message, signed_message);

        const auto second_signed_message = assigned.sign(message);
        auto aliased_pk = pk;
        EXPECT_TRUE(Dilithium::sign_open(aliased_pk,
                                         second_signed_message,
                                         aliased_pk));
        EXPECT_EQ(message, aliased_pk);
    }

    TEST(DilithumTest, imported_keys_require_exact_sizes) {
        Dilithium generated;
        const auto pk = generated.getPK();
        const auto sk = generated.getSK();

        EXPECT_NO_THROW(Dilithium(pk, sk));

        for (const auto size : std::array<size_t, 3>{0, CRYPTO_PUBLICKEYBYTES - 1,
                                                     CRYPTO_PUBLICKEYBYTES + 1}) {
            auto invalid_pk = pk;
            invalid_pk.resize(size);
            EXPECT_THROW(Dilithium(invalid_pk, sk), std::invalid_argument);
        }

        for (const auto size : std::array<size_t, 3>{0, CRYPTO_SECRETKEYBYTES - 1,
                                                     CRYPTO_SECRETKEYBYTES + 1}) {
            auto invalid_sk = sk;
            invalid_sk.resize(size);
            EXPECT_THROW(Dilithium(pk, invalid_sk), std::invalid_argument);
        }
    }

    TEST(DilithumTest, signing_revalidates_protected_secret_key) {
        MutableDilithium dilithium;
        const auto sk = dilithium.getSK();
        const std::vector<uint8_t> message{1, 2, 3};

        for (const auto size : std::array<size_t, 3>{0, CRYPTO_SECRETKEYBYTES - 1,
                                                     CRYPTO_SECRETKEYBYTES + 1}) {
            auto invalid_sk = sk;
            invalid_sk.resize(size);
            dilithium.replaceSecretKey(invalid_sk);
            EXPECT_THROW(dilithium.sign(message), std::invalid_argument);
        }
    }

    TEST(DilithumTest, verification_requires_exact_public_key_and_clears_output) {
        Dilithium dilithium;
        const std::vector<uint8_t> message{4, 3, 2, 1};
        const auto signed_message = dilithium.sign(message);
        const auto pk = dilithium.getPK();

        for (const auto size : std::array<size_t, 3>{0, CRYPTO_PUBLICKEYBYTES - 1,
                                                     CRYPTO_PUBLICKEYBYTES + 1}) {
            auto invalid_pk = pk;
            invalid_pk.resize(size);
            std::vector<uint8_t> output(19, 0xa5);
            EXPECT_FALSE(Dilithium::sign_open(output, signed_message, invalid_pk));
            EXPECT_TRUE(output.empty());
        }

        std::vector<uint8_t> output(19, 0xa5);
        EXPECT_TRUE(Dilithium::sign_open(output, signed_message, pk));
        EXPECT_EQ(message, output);
    }

    TEST(DilithumTest, signed_message_boundary_lengths_are_safe) {
        Dilithium dilithium;
        const auto pk = dilithium.getPK();

        const std::vector<uint8_t> empty_message;
        auto valid_exact = dilithium.sign(empty_message);
        ASSERT_EQ(static_cast<size_t>(CRYPTO_BYTES), valid_exact.size());
        std::vector<uint8_t> valid_exact_output(11, 0x3c);
        EXPECT_TRUE(Dilithium::sign_open(valid_exact_output, valid_exact, pk));
        EXPECT_TRUE(valid_exact_output.empty());

        for (const auto size : std::array<size_t, 2>{0, CRYPTO_BYTES - 1}) {
            std::vector<uint8_t> signed_message(size, 0xa5);
            std::vector<uint8_t> output(11, 0x3c);

            EXPECT_TRUE(Dilithium::extract_message(signed_message).empty());
            EXPECT_TRUE(Dilithium::extract_signature(signed_message).empty());
            EXPECT_FALSE(Dilithium::sign_open(output, signed_message, pk));
            EXPECT_TRUE(output.empty());
        }

        std::vector<uint8_t> exact(CRYPTO_BYTES, 0xa5);
        EXPECT_TRUE(Dilithium::extract_message(exact).empty());
        EXPECT_EQ(exact, Dilithium::extract_signature(exact));
        std::vector<uint8_t> exact_output(11, 0x3c);
        EXPECT_FALSE(Dilithium::sign_open(exact_output, exact, pk));
        EXPECT_TRUE(exact_output.empty());

        std::vector<uint8_t> plus_one(CRYPTO_BYTES + 1, 0xa5);
        plus_one.back() = 0x42;
        EXPECT_EQ(std::vector<uint8_t>{0x42}, Dilithium::extract_message(plus_one));
        EXPECT_EQ(std::vector<uint8_t>(CRYPTO_BYTES, 0xa5),
                  Dilithium::extract_signature(plus_one));
        std::vector<uint8_t> plus_one_output(11, 0x3c);
        EXPECT_FALSE(Dilithium::sign_open(plus_one_output, plus_one, pk));
        EXPECT_TRUE(plus_one_output.empty());
    }

}
