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
    auto sk = xmss.getSK();

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "seed:" << seed.size() << " bytes\n" << bin2hstr(seed, 48) << std::endl;
    std::cout << "pk  :" << pk.size() << " bytes\n" << bin2hstr(pk, 48) << std::endl;
    std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 48) << std::endl;

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

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
    std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;
    EXPECT_EQ(xmss.getIndex(), 1);

    auto signature2 = xmss.sign(data);

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
    std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;

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
    auto sk = xmss.getSK();
    std::cout << std::endl;
    std::cout << "seed:" << seed.size() << " bytes\n" << bin2hstr(seed, 32) << std::endl;
    std::cout << "pk  :" << pk.size() << " bytes\n" << bin2hstr(pk, 32) << std::endl;
    std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 32) << std::endl;

    auto signature = xmss.sign(data);

    EXPECT_EQ(data, data_ref);

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
    std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;

    EXPECT_TRUE(XmssBasic::verify(data, signature, pk));

    signature[1] += 1;
    EXPECT_FALSE(XmssBasic::verify(data, signature, xmss.getPK()));
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
}

TEST(XmssFast, IndexBackwards)
{
    std::vector<unsigned char> seed(48, 0);

    XmssFast xmss1(seed, 4);

    xmss1.setIndex(10);
    EXPECT_EQ(10, xmss1.getIndex());

    ASSERT_THROW( xmss1.setIndex(2), std::invalid_argument);
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
