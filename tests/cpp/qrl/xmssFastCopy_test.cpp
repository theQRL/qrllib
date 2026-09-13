// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <xmssFast.h>
#include <xmssBasic.h>
#include <stdexcept>
#include <memory>
#include <utility>
#include "gtest/gtest.h"

namespace
{
std::vector<unsigned char> testSeed()
{
    std::vector<unsigned char> seed(48);
    for (size_t i = 0; i < seed.size(); i++) {
        seed[i] = static_cast<unsigned char>(i);
    }
    return seed;
}

TMESSAGE testMessage()
{
    TMESSAGE msg(32);
    for (size_t i = 0; i < msg.size(); i++) {
        msg[i] = static_cast<unsigned char>(0xa0 + i);
    }
    return msg;
}

class XmssFastCopy : public ::testing::TestWithParam<unsigned char> {};

TEST_P(XmssFastCopy, HeapCopyOfDestroyedTemporarySignsCorrectly)
{
    const auto height = GetParam();
    const auto seed = testSeed();
    const auto msg = testMessage();

    XmssFast reference(seed, height, eHashFunction::SHA2_256);
    const auto pk = reference.getPK();
    const auto expected0 = reference.sign(msg);
    const auto expected1 = reference.sign(msg);

    std::unique_ptr<XmssFast> survivor;
    {
        XmssFast tmp(seed, height, eHashFunction::SHA2_256);
        survivor.reset(new XmssFast(tmp));
    }

    const auto sig0 = survivor->sign(msg);
    EXPECT_TRUE(XmssFast::verify(msg, sig0, pk));
    EXPECT_EQ(expected0, sig0);
    EXPECT_EQ(1u, survivor->getIndex());

    const auto sig1 = survivor->sign(msg);
    EXPECT_TRUE(XmssFast::verify(msg, sig1, pk));
    EXPECT_EQ(expected1, sig1);
}

TEST_P(XmssFastCopy, HeapMoveOfDestroyedTemporarySignsCorrectly)
{
    const auto height = GetParam();
    const auto seed = testSeed();
    const auto msg = testMessage();

    XmssFast reference(seed, height, eHashFunction::SHA2_256);
    const auto pk = reference.getPK();
    const auto expected0 = reference.sign(msg);

    std::unique_ptr<XmssFast> survivor;
    {
        XmssFast tmp(seed, height, eHashFunction::SHA2_256);
        survivor.reset(new XmssFast(std::move(tmp)));
    }

    const auto sig0 = survivor->sign(msg);
    EXPECT_TRUE(XmssFast::verify(msg, sig0, pk));
    EXPECT_EQ(expected0, sig0);
}

TEST_P(XmssFastCopy, CopyAndMoveAssignmentRebindState)
{
    const auto height = GetParam();
    const auto seed = testSeed();
    const auto msg = testMessage();

    XmssFast reference(seed, height, eHashFunction::SHA2_256);
    const auto pk = reference.getPK();
    const auto expected0 = reference.sign(msg);

    XmssFast copyAssigned(seed, 4, eHashFunction::SHAKE_128);
    {
        XmssFast tmp(seed, height, eHashFunction::SHA2_256);
        copyAssigned = tmp;
    }
    const auto sigCopy = copyAssigned.sign(msg);
    EXPECT_TRUE(XmssFast::verify(msg, sigCopy, pk));
    EXPECT_EQ(expected0, sigCopy);

    XmssFast moveAssigned(seed, 4, eHashFunction::SHAKE_128);
    {
        XmssFast tmp(seed, height, eHashFunction::SHA2_256);
        moveAssigned = std::move(tmp);
    }
    const auto sigMove = moveAssigned.sign(msg);
    EXPECT_TRUE(XmssFast::verify(msg, sigMove, pk));
    EXPECT_EQ(expected0, sigMove);
}

TEST_P(XmssFastCopy, CopyOfAdvancedTraversalStateSignsCorrectly)
{
    const auto height = GetParam();
    const auto seed = testSeed();
    const auto msg = testMessage();

    XmssFast reference(seed, height, eHashFunction::SHA2_256);
    const auto pk = reference.getPK();
    reference.sign(msg);
    const auto expected1 = reference.sign(msg);
    const auto expected2 = reference.sign(msg);

    XmssFast advanced(seed, height, eHashFunction::SHA2_256);
    advanced.sign(msg);
    XmssFast copied(advanced);
    ASSERT_EQ(1u, copied.getIndex());

    const auto sig1 = copied.sign(msg);
    EXPECT_TRUE(XmssFast::verify(msg, sig1, pk));
    EXPECT_EQ(expected1, sig1);

    const auto srcSig1 = advanced.sign(msg);
    EXPECT_EQ(expected1, srcSig1);

    const auto sig2 = copied.sign(msg);
    EXPECT_EQ(expected2, sig2);
}

TEST_P(XmssFastCopy, CopiedSignerStateIsIndependentOfSource)
{
    const auto height = GetParam();
    const auto seed = testSeed();
    const auto msg = testMessage();

    XmssFast reference(seed, height, eHashFunction::SHA2_256);
    const auto pk = reference.getPK();
    const auto expected0 = reference.sign(msg);
    const auto expected1 = reference.sign(msg);

    XmssFast source(seed, height, eHashFunction::SHA2_256);
    {
        XmssFast copy(source);
        EXPECT_EQ(expected0, copy.sign(msg));
        EXPECT_EQ(expected1, copy.sign(msg));
        EXPECT_EQ(0u, source.getIndex());
    }
    EXPECT_EQ(expected0, source.sign(msg));
    EXPECT_TRUE(XmssFast::verify(msg, source.sign(msg), pk));
}

INSTANTIATE_TEST_SUITE_P(Heights, XmssFastCopy, ::testing::Values(4, 6, 8, 10));
}

namespace
{
TEST(XmssBasicExhaustion, SigningPastTheLastLeafThrows)
{
    std::vector<unsigned char> seed(48, 7);
    XmssBasic xmss(seed, 4, eHashFunction::SHA2_256, eAddrFormatType::SHA256_2X, 16);
    TMESSAGE msg(32, 0x5a);
    const auto pk = xmss.getPK();

    for (unsigned int i = 0; i < 16; i++) {
        EXPECT_EQ(i, xmss.getIndex());
        EXPECT_TRUE(XmssBasic::verify(msg, xmss.sign(msg), pk));
    }
    EXPECT_EQ(16u, xmss.getIndex());
    EXPECT_EQ(0u, xmss.getRemainingSignatures());
    EXPECT_THROW(xmss.sign(msg), std::invalid_argument);

    XmssFast fast(seed, 4, eHashFunction::SHA2_256);
    for (unsigned int i = 0; i < 16; i++) {
        EXPECT_TRUE(XmssFast::verify(msg, fast.sign(msg), fast.getPK()));
    }
    EXPECT_THROW(fast.sign(msg), std::invalid_argument);
}
}
