// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <sys/types.h>
#include <vector>

#if defined(QRLLIB_TEST_DILITHIUM_ENTROPY_FAILURE)
#include <dilithium/ref/api.h>
#elif defined(QRLLIB_TEST_KYBER_ENTROPY_FAILURE)
#include <kyber/ref/api.h>
#include <kyber/ref/kex.h>
#else
#error "Select a reference implementation"
#endif

namespace {

size_t entropy_call_count;
size_t failing_entropy_call;
unsigned char next_entropy_byte;

bool all_zero(const std::vector<unsigned char> &buffer)
{
    return std::all_of(buffer.begin(), buffer.end(),
                       [](unsigned char value) { return value == 0; });
}

class EntropyFailureTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        entropy_call_count = 0;
        failing_entropy_call = 1;
        next_entropy_byte = 1;
    }
};

}  // namespace

ssize_t qrllib_system_random_test_getrandom(unsigned char *buffer,
                                            size_t length,
                                            unsigned int)
{
    ++entropy_call_count;
    if (entropy_call_count == failing_entropy_call) {
        errno = EIO;
        return -1;
    }

    for (size_t i = 0; i < length; ++i) {
        buffer[i] = next_entropy_byte++;
    }
    return static_cast<ssize_t>(length);
}

#if defined(QRLLIB_TEST_DILITHIUM_ENTROPY_FAILURE)

TEST_F(EntropyFailureTest, KeypairFailureClearsBothOutputs)
{
    std::vector<unsigned char> public_key(CRYPTO_PUBLICKEYBYTES, 0xa5);
    std::vector<unsigned char> secret_key(CRYPTO_SECRETKEYBYTES, 0xa5);

    EXPECT_EQ(-1, crypto_sign_keypair(public_key.data(), secret_key.data()));
    EXPECT_TRUE(all_zero(public_key));
    EXPECT_TRUE(all_zero(secret_key));
}

#elif defined(QRLLIB_TEST_KYBER_ENTROPY_FAILURE)

TEST_F(EntropyFailureTest, KeypairClearsOutputsWhenInitialEntropyFails)
{
    std::vector<unsigned char> public_key(CRYPTO_PUBLICKEYBYTES, 0xa5);
    std::vector<unsigned char> secret_key(CRYPTO_SECRETKEYBYTES, 0xa5);

    EXPECT_EQ(-1, crypto_kem_keypair(public_key.data(), secret_key.data()));
    EXPECT_TRUE(all_zero(public_key));
    EXPECT_TRUE(all_zero(secret_key));
}

TEST_F(EntropyFailureTest, KeypairClearsOutputsWhenRejectionEntropyFails)
{
    failing_entropy_call = 2;
    std::vector<unsigned char> public_key(CRYPTO_PUBLICKEYBYTES, 0xa5);
    std::vector<unsigned char> secret_key(CRYPTO_SECRETKEYBYTES, 0xa5);

    EXPECT_EQ(-1, crypto_kem_keypair(public_key.data(), secret_key.data()));
    EXPECT_TRUE(all_zero(public_key));
    EXPECT_TRUE(all_zero(secret_key));
}

TEST_F(EntropyFailureTest, EncapsulationFailureClearsBothOutputs)
{
    std::vector<unsigned char> public_key(CRYPTO_PUBLICKEYBYTES, 0);
    std::vector<unsigned char> ciphertext(CRYPTO_CIPHERTEXTBYTES, 0xa5);
    std::vector<unsigned char> shared_secret(CRYPTO_BYTES, 0xa5);

    EXPECT_EQ(-1, crypto_kem_enc(ciphertext.data(),
                                shared_secret.data(),
                                public_key.data()));
    EXPECT_TRUE(all_zero(ciphertext));
    EXPECT_TRUE(all_zero(shared_secret));
}

TEST_F(EntropyFailureTest, UakeInitFailureClearsEveryOutput)
{
    std::vector<unsigned char> send(KYBER_UAKE_SENDABYTES, 0xa5);
    std::vector<unsigned char> temporary_key(KYBER_SYMBYTES, 0xa5);
    std::vector<unsigned char> secret_key(CRYPTO_SECRETKEYBYTES, 0xa5);
    std::vector<unsigned char> peer_public_key(CRYPTO_PUBLICKEYBYTES, 0);

    kyber_uake_initA(send.data(),
                     temporary_key.data(),
                     secret_key.data(),
                     peer_public_key.data());

    EXPECT_TRUE(all_zero(send));
    EXPECT_TRUE(all_zero(temporary_key));
    EXPECT_TRUE(all_zero(secret_key));
}

TEST_F(EntropyFailureTest, UakeSharedFailureClearsEveryOutput)
{
    std::vector<unsigned char> send(KYBER_UAKE_SENDBBYTES, 0xa5);
    std::vector<unsigned char> shared_key(KYBER_SYMBYTES, 0xa5);
    std::vector<unsigned char> received(KYBER_UAKE_SENDABYTES, 0);
    std::vector<unsigned char> secret_key(CRYPTO_SECRETKEYBYTES, 0);

    kyber_uake_sharedB(send.data(),
                       shared_key.data(),
                       received.data(),
                       secret_key.data());

    EXPECT_TRUE(all_zero(send));
    EXPECT_TRUE(all_zero(shared_key));
}

TEST_F(EntropyFailureTest, AkeInitFailureClearsEveryOutput)
{
    std::vector<unsigned char> send(KYBER_AKE_SENDABYTES, 0xa5);
    std::vector<unsigned char> temporary_key(KYBER_SYMBYTES, 0xa5);
    std::vector<unsigned char> secret_key(CRYPTO_SECRETKEYBYTES, 0xa5);
    std::vector<unsigned char> peer_public_key(CRYPTO_PUBLICKEYBYTES, 0);

    kyber_ake_initA(send.data(),
                    temporary_key.data(),
                    secret_key.data(),
                    peer_public_key.data());

    EXPECT_TRUE(all_zero(send));
    EXPECT_TRUE(all_zero(temporary_key));
    EXPECT_TRUE(all_zero(secret_key));
}

TEST_F(EntropyFailureTest, AkeSharedFailureClearsEveryOutput)
{
    std::vector<unsigned char> send(KYBER_AKE_SENDBBYTES, 0xa5);
    std::vector<unsigned char> shared_key(KYBER_SYMBYTES, 0xa5);
    std::vector<unsigned char> received(KYBER_AKE_SENDABYTES, 0);
    std::vector<unsigned char> secret_key(CRYPTO_SECRETKEYBYTES, 0);
    std::vector<unsigned char> public_key(CRYPTO_PUBLICKEYBYTES, 0);

    kyber_ake_sharedB(send.data(),
                      shared_key.data(),
                      received.data(),
                      secret_key.data(),
                      public_key.data());

    EXPECT_TRUE(all_zero(send));
    EXPECT_TRUE(all_zero(shared_key));
}

#endif
