// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <cstdint>
#include <qrlDescriptor.h>
#include "gtest/gtest.h"

namespace {

TEST(QRL_Descriptor, checkAttributes1)
{
    QRLDescriptor desc(
            eHashFunction::SHA2_256,
            eSignatureType::XMSS,
            10,
            eAddrFormatType::SHA256_2X
    );

    EXPECT_TRUE(desc.getHashFunction()==eHashFunction::SHA2_256);
    EXPECT_TRUE(desc.getHashFunction()!=eHashFunction::SHAKE_128);
    EXPECT_TRUE(desc.getSignatureType()==eSignatureType::XMSS);

    EXPECT_EQ(10, desc.getHeight());

    std::vector<uint8_t> expected_descriptor_bytes{0x00, 0x05, 0x00};
    EXPECT_EQ(expected_descriptor_bytes, desc.getBytes());
}

TEST(QRL_Descriptor, checkAttributes2)
{
    QRLDescriptor desc(
            eHashFunction::SHAKE_128,
            eSignatureType::XMSS,
            16,
            eAddrFormatType::SHA256_2X
    );

    EXPECT_TRUE(desc.getHashFunction()!=eHashFunction::SHA2_256);
    EXPECT_TRUE(desc.getHashFunction()==eHashFunction::SHAKE_128);
    EXPECT_TRUE(desc.getSignatureType()==eSignatureType::XMSS);
    EXPECT_TRUE(desc.getAddrFormatType()==eAddrFormatType::SHA256_2X);
    EXPECT_EQ(16, desc.getHeight());

    std::vector<uint8_t> expected_descriptor_bytes{0x01, 0x08, 0x00};
    EXPECT_EQ(expected_descriptor_bytes, desc.getBytes());
}

TEST(QRL_Descriptor, checkAttributesFromBytes)
{
    QRLDescriptor desc = QRLDescriptor::fromBytes({0x01, 0x08, 0x00});

    EXPECT_TRUE(desc.getHashFunction()!=eHashFunction::SHA2_256);
    EXPECT_TRUE(desc.getHashFunction()==eHashFunction::SHAKE_128);
    EXPECT_TRUE(desc.getSignatureType()==eSignatureType::XMSS);
    EXPECT_TRUE(desc.getAddrFormatType()==eAddrFormatType::SHA256_2X);
    EXPECT_EQ(16, desc.getHeight());

    std::vector<uint8_t> expected_descriptor_bytes{0x01, 0x08, 0x00};
    EXPECT_EQ(expected_descriptor_bytes, desc.getBytes());
}

TEST(QRL_Descriptor, RejectsMalformedEncodings)
{
    EXPECT_THROW(QRLDescriptor::fromBytes({0x01, 0x08}), std::invalid_argument);
    EXPECT_THROW(QRLDescriptor::fromBytes({0x03, 0x08, 0x00}), std::invalid_argument);
    EXPECT_THROW(QRLDescriptor::fromBytes({0x11, 0x08, 0x00}), std::invalid_argument);
    EXPECT_THROW(QRLDescriptor::fromBytes({0x01, 0x18, 0x00}), std::invalid_argument);
    EXPECT_THROW(QRLDescriptor::fromBytes({0x01, 0x08, 0x01}), std::invalid_argument);
    EXPECT_THROW(QRLDescriptor::fromBytes({0x01, 0x00, 0x00}), std::invalid_argument);
    EXPECT_THROW(QRLDescriptor::fromBytes({0x01, 0x01, 0x00}), std::invalid_argument);
}

TEST(QRL_Descriptor, AcceptsHighestEncodableSupportedHeight)
{
    const auto desc = QRLDescriptor::fromBytes({0x02, 0x0f, 0x00});
    EXPECT_EQ(eHashFunction::SHAKE_256, desc.getHashFunction());
    EXPECT_EQ(30, desc.getHeight());
}

TEST(QRL_Descriptor, RejectsMalformedExtendedObjects)
{
    std::vector<uint8_t> seed(51, 0);
    seed[0] = 0x03;
    EXPECT_THROW(QRLDescriptor::fromExtendedSeed(seed), std::invalid_argument);

    std::vector<uint8_t> public_key(67, 0);
    public_key[2] = 1;
    EXPECT_THROW(QRLDescriptor::fromExtendedPK(public_key), std::invalid_argument);
}

}
