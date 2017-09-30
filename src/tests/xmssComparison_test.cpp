// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <algsxmss.h>
#include <xmss.h>
#include <iostream>
#include "gtest/gtest.h"
#include <xmssFast.h>
#include <misc.h>

constexpr uint8_t XMSS_HEIGHT = 4;
constexpr uint32_t XMSS_N = 48;
constexpr uint32_t XMSS_W = 16;
constexpr uint32_t XMSS_K = 2;

template <typename T>
class XmssComparisonTest : public ::testing::Test
{
public:
    using TXMSS1 = typename T::T1;
    using TXMSS2 = typename T::T2;
};

template<typename T, typename U>
struct TypePAIR
{
    using T1 = T;
    using T2 = U;
};

typedef ::testing::Types<
        TypePAIR<Xmss, XmssFast>
> xmssTypes;

TYPED_TEST_CASE(XmssComparisonTest, xmssTypes);

TYPED_TEST(XmssComparisonTest, KeyCreation) {
    std::vector<unsigned char> seed(XMSS_N, 0);

    typename TestFixture::TXMSS1 xmss1(seed, XMSS_HEIGHT);
    typename TestFixture::TXMSS2 xmss2(seed, XMSS_HEIGHT);

    auto PK1 = xmss1.getPK();
    auto SK1 = xmss1.getSK();

    auto PK2 = xmss2.getPK();
    auto SK2 = xmss2.getSK();

    EXPECT_EQ(PK1, PK2);
    EXPECT_EQ(SK1, SK2);
}

TYPED_TEST(XmssComparisonTest, Sign) {
    std::vector<unsigned char> seed(XMSS_N, 0);

    typename TestFixture::TXMSS1 xmss1(seed, XMSS_HEIGHT);
    typename TestFixture::TXMSS2 xmss2(seed, XMSS_HEIGHT);

    std::string message = "This is a test message";
    std::vector<unsigned char> data(message.begin(), message.end());

    auto signature1 = xmss1.sign(data);
    auto signature2 = xmss2.sign(data);

    EXPECT_EQ(signature1, signature2);
}

TYPED_TEST(XmssComparisonTest, SignTwice) {
    std::vector<unsigned char> seed(XMSS_N, 0);

    typename TestFixture::TXMSS1 xmss1(seed, XMSS_HEIGHT);
    typename TestFixture::TXMSS2 xmss2(seed, XMSS_HEIGHT);

    std::string message = "This is a test message";
    std::vector<unsigned char> data(message.begin(), message.end());

    auto signature1 = xmss1.sign(data);
    auto signature2 = xmss2.sign(data);
    signature1 = xmss1.sign(data);
    signature2 = xmss2.sign(data);

    auto hstr_sig1 = bin2hstr(signature1);
    auto hstr_sig2 = bin2hstr(signature2);

    EXPECT_EQ(hstr_sig1, hstr_sig2);
//    EXPECT_EQ(signature1, signature2);
}

TYPED_TEST(XmssComparisonTest, SignThreeTimesVsShift) {
    std::vector<unsigned char> seed(XMSS_N, 0);

    typename TestFixture::TXMSS1 xmss1(seed, XMSS_HEIGHT);
    typename TestFixture::TXMSS2 xmss2(seed, XMSS_HEIGHT);

    std::string message = "This is a test message";
    std::vector<unsigned char> data(message.begin(), message.end());

    xmss1.setIndex(2);
    auto signature1 = xmss1.sign(data);
    xmss2.sign(data);
    xmss2.sign(data);
    auto signature2 = xmss2.sign(data);

    auto hstr_sig1 = bin2hstr(signature1);
    auto hstr_sig2 = bin2hstr(signature2);

    EXPECT_EQ(hstr_sig1, hstr_sig2);
}

TYPED_TEST(XmssComparisonTest, SignIndexShift) {
    std::vector<unsigned char> seed(XMSS_N, 0);

    typename TestFixture::TXMSS1 xmss1(seed, XMSS_HEIGHT);
    typename TestFixture::TXMSS2 xmss2(seed, XMSS_HEIGHT);

    std::string message = "This is a test message";
    std::vector<unsigned char> data(message.begin(), message.end());

    xmss1.setIndex(1);
    xmss2.setIndex(1);

    auto signature1 = xmss1.sign(data);
    auto signature2 = xmss2.sign(data);

    auto hstr_sig1 = bin2hstr(signature1);
    auto hstr_sig2 = bin2hstr(signature2);

    EXPECT_EQ(hstr_sig1, hstr_sig2);
//    EXPECT_EQ(signature1, signature2);
}
