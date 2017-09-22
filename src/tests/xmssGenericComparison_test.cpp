// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <algsxmss.h>
#include <xmss.h>
#include <vector>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>
#include <xmssFast.h>

constexpr uint8_t XMSS_HEIGHT = 4;
constexpr uint32_t XMSS_N = 48;
constexpr uint32_t XMSS_W = 16;
constexpr uint32_t XMSS_K = 2;

template <typename T>
class XmssGenericComparisonTest : public ::testing::Test
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

TYPED_TEST_CASE(XmssGenericComparisonTest, xmssTypes);

TYPED_TEST(XmssGenericComparisonTest, KeyCreation) {
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
