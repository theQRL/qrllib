// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <algsxmss.h>
#include <xmss.h>
#include <vector>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>
#include <xmssFast.h>

namespace {
    constexpr uint8_t XMSS_HEIGHT = 4;

    template <typename T>
    class XmssGenericTest : public ::testing::Test
    {
    public:
        using TXMSS = T;
    };

    typedef ::testing::Types<Xmss, XmssFast> xmssTypes;
    TYPED_TEST_CASE(XmssGenericTest, xmssTypes);

    TYPED_TEST(XmssGenericTest, Instantiation) {
        std::vector<unsigned char> seed(48, 0);

        typename TestFixture::TXMSS xmss(seed, XMSS_HEIGHT);

        auto pk = xmss.getPK();
        auto sk = xmss.getSK();

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "seed:" << seed.size() << " bytes\n" << bin2hstr(seed, 48) << std::endl;
        std::cout << "pk  :" << pk.size() << " bytes\n" << bin2hstr(pk, 48) << std::endl;
        std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 48) << std::endl;

        EXPECT_EQ(seed, xmss.getSeed());
    }

    TYPED_TEST(XmssGenericTest, SignatureLen) {
        std::vector<unsigned char> seed(48, 0);

        typename TestFixture::TXMSS xmss4(seed, 4);
        EXPECT_EQ(2308, xmss4.getSignatureSize());

        typename TestFixture::TXMSS xmss6(seed, 6);
        EXPECT_EQ(2372, xmss6.getSignatureSize());
    }

    TYPED_TEST(XmssGenericTest, Sign) {
        std::vector<unsigned char> seed(48, 0);

        typename TestFixture::TXMSS xmss(seed, XMSS_HEIGHT);

        std::string message = "This is a test message";
        std::vector<unsigned char> data(message.begin(), message.end());

        auto signature = xmss.sign(data);

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
        std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;
    }

    TYPED_TEST(XmssGenericTest, SignManyTimesIndexMoves) {
        std::vector<unsigned char> seed(48, 0);

        typename TestFixture::TXMSS xmss(seed, XMSS_HEIGHT);

        std::string message = "This is a test message";
        std::vector<unsigned char> data(message.begin(), message.end());

        for(int i=0; i < 10; i++)
        {
            EXPECT_EQ(i, xmss.getIndex());
            auto sk = xmss.getSK();
            auto pk = xmss.getPK();
            std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 32) << std::endl;
            std::cout << "pk  :" << sk.size() << " bytes\n" << bin2hstr(pk, 32) << std::endl;
            auto signature = xmss.sign(data);
            std::cout << "sign:" << sk.size() << " bytes\n" << bin2hstr(signature, 32) << std::endl;

            EXPECT_EQ(i+1, xmss.getIndex());
        }
    }

    TYPED_TEST(XmssGenericTest, SignManyTimesSignatureChanges) {
        std::vector<unsigned char> seed(48, 0);

        typename TestFixture::TXMSS xmss(seed, XMSS_HEIGHT);

        std::string message = "This is a test message";
        std::vector<unsigned char> data(message.begin(), message.end());

        for(int i=0; i < 10; i++)
        {
            EXPECT_EQ(i, xmss.getIndex());
            auto sk = xmss.getSK();
            auto pk = xmss.getPK();

            std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 32) << std::endl;
            std::cout << "pk  :" << sk.size() << " bytes\n" << bin2hstr(pk, 32) << std::endl;
            auto signature = xmss.sign(data);

            EXPECT_EQ(i+1, xmss.getIndex());
        }
    }

    TYPED_TEST(XmssGenericTest, Verify) {
        std::vector<unsigned char> seed(48, 0);

        typename TestFixture::TXMSS xmss(seed, XMSS_HEIGHT);

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

        EXPECT_TRUE(Xmss::verify(data, signature, pk, XMSS_HEIGHT));

        signature[1] += 1;
        EXPECT_FALSE(Xmss::verify(data, signature, xmss.getPK(), XMSS_HEIGHT));
    }

}
