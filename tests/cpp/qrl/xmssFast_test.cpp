// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <xmss-alt/algsxmss.h>
#include <xmssBasic.h>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>
#include <xmssFast.h>

namespace
{
#define XMSS_HEIGHT 8

TEST(XmssFast, Instantiation)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss(seed, XMSS_HEIGHT);

    auto pk = xmss.getPK();


    EXPECT_EQ(seed, xmss.getSeed());
}

TEST(XmssFast, SignatureLen)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss4(seed, 4);
    EXPECT_EQ(2308, xmss4.getSignatureSize());

    XmssFast xmss6(seed, 6);
    EXPECT_EQ(2372, xmss6.getSignatureSize());
}

TEST(XmssFast, Sign)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss(seed, XMSS_HEIGHT);

    std::string message = "This is a test message";
    std::vector<unsigned char> data(message.begin(), message.end());
    EXPECT_EQ(xmss.getIndex(), 0);

    auto signature = xmss.sign(data);

    EXPECT_EQ(xmss.getIndex(), 1);

    auto signature2 = xmss.sign(data);


    EXPECT_NE(bin2hstr(signature), bin2hstr(signature2));
    EXPECT_EQ(xmss.getIndex(), 2);
}

TEST(XmssFast, Verify)
{
    std::vector<unsigned char> seed(48, 0);

    XmssBasic xmss(seed, XMSS_HEIGHT, eHashFunction::SHAKE_128, eAddrFormatType::SHA256_2X);

    std::string message = "This is a test message";
    std::vector<unsigned char> data_ref(message.begin(), message.end());
    std::vector<unsigned char> data(message.begin(), message.end());

    auto pk = xmss.getPK();

    auto signature = xmss.sign(data);

    EXPECT_EQ(data, data_ref);


    EXPECT_TRUE(XmssBasic::verify(data, signature, pk));

    signature[1] += 1;
    EXPECT_FALSE(XmssBasic::verify(data, signature, xmss.getPK()));
}

TEST(XmssFast, SignWithW4)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss(seed, XMSS_HEIGHT);
    xmss.initialize_tree(4);

    std::string message = "This is a test message";
    std::vector<unsigned char> data(message.begin(), message.end());
    EXPECT_EQ(xmss.getIndex(), 0);

    auto signature = xmss.sign(data);

    EXPECT_EQ(xmss.getIndex(), 1);

    auto signature2 = xmss.sign(data);


    EXPECT_NE(bin2hstr(signature), bin2hstr(signature2));
    EXPECT_EQ(xmss.getIndex(), 2);
}

TEST(XmssFast, VerifyWithW4)
{
    std::vector<unsigned char> seed(48, 0);

    XmssBasic xmss(seed, 10, eHashFunction::SHA2_256,
            eAddrFormatType::SHA256_2X, 4);

    std::string message = "56454c9621c549cd05c112de496ba32f";

    std::vector<unsigned char> data_ref(message.begin(), message.end());
    std::vector<unsigned char> data = hstr2bin("56454c9621c549cd05c112de496ba32f");

    auto pk = xmss.getPK();

    auto signature = xmss.sign(data);


    EXPECT_TRUE(XmssBasic::verify(data, signature, pk, 4));
    EXPECT_FALSE(XmssBasic::verify(data, signature, xmss.getPK()));

    signature[1] += 1;
    EXPECT_FALSE(XmssBasic::verify(data, signature, xmss.getPK(), 4));
}

TEST(XmssFast, SignIndexShift)
{
    std::vector<unsigned char> seed(48, 0);

    XmssBasic xmss1(seed, 4, eHashFunction::SHAKE_128, eAddrFormatType::SHA256_2X);
    XmssFast xmss2(seed, 4);

    std::string message = "This is a test message";
    std::vector<unsigned char> data(message.begin(), message.end());

    xmss1.setIndex(1);
    xmss2.setIndex(1);

    auto signature1 = xmss1.sign(data);
    auto signature2 = xmss2.sign(data);

    auto hstr_sig1 = bin2hstr(signature1);
    auto hstr_sig2 = bin2hstr(signature2);

    EXPECT_EQ(hstr_sig1, hstr_sig2);
}

TEST(XmssFast, BadInputConstructor)
{
    std::vector<unsigned char> seed(48, 0);

    EXPECT_THROW(XmssFast xmss(seed, 3), std::invalid_argument);
    EXPECT_THROW(XmssFast xmss(seed, 4, static_cast<eHashFunction>(3)), std::invalid_argument);
    EXPECT_THROW(XmssFast xmss(seed, 4, eHashFunction::SHAKE_128,
                               static_cast<eAddrFormatType>(1)), std::invalid_argument);

    std::vector<unsigned char> short_seed(47, 0);
    EXPECT_THROW(XmssFast xmss(short_seed, 4), std::invalid_argument);

    std::vector<unsigned char> malformed_extended_seed(51, 0);
    malformed_extended_seed[0] = 3;
    EXPECT_THROW(XmssFast xmss(malformed_extended_seed), std::invalid_argument);
}

TEST(XmssFast, BadInputVerify)
{
    TMESSAGE message(2, 0);
    TSIGNATURE signature(48, 0);
    TKEY pk(67, 0);

    EXPECT_FALSE(XmssFast::verify(message, signature, pk));

    TSIGNATURE signature2(2287, 0);
    EXPECT_FALSE(XmssFast::verify(message, signature2, pk));
}

TEST(XmssFast, IndexForward)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss1(seed, 4);

    xmss1.setIndex(1);
    EXPECT_EQ(1, xmss1.getIndex());

    xmss1.setIndex(2);
    EXPECT_EQ(2, xmss1.getIndex());

    xmss1.setIndex(10);
    EXPECT_EQ(10, xmss1.getIndex());
}

TEST(XmssFast, IndexLimit)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss1(seed, 4);

    ASSERT_THROW( xmss1.setIndex(100), std::invalid_argument);
    EXPECT_EQ(16u, xmss1.setIndex(16));
    EXPECT_EQ(0u, xmss1.getRemainingSignatures());
    EXPECT_THROW(xmss1.sign({0x01}), std::invalid_argument);
    EXPECT_THROW(xmss1.setIndex(17), std::invalid_argument);
}

TEST(XmssFast, IndexBackwards)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss1(seed, 4);

    xmss1.setIndex(10);
    EXPECT_EQ(10, xmss1.getIndex());

    ASSERT_THROW( xmss1.setIndex(2), std::invalid_argument);
}

TEST(XmssFast, ReinitializationCannotResetSigningIndex)
{
    std::vector<unsigned char> seed(48, 0);
    XmssFast xmss(seed, 4);
    const std::vector<unsigned char> message{0x01};

    (void)xmss.sign(message);
    ASSERT_EQ(1u, xmss.getIndex());
    EXPECT_THROW(xmss.initialize_tree(), std::invalid_argument);
    EXPECT_EQ(1u, xmss.getIndex());
}

TEST(XmssFast, IndexSame)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss1(seed, 4);

    xmss1.setIndex(1);
    EXPECT_EQ(1, xmss1.getIndex());

    xmss1.setIndex(10);
    EXPECT_EQ(10, xmss1.getIndex());

    xmss1.setIndex(10);
    EXPECT_EQ(10, xmss1.getIndex());
}

}
