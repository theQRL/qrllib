#include "gtest/gtest.h"

extern "C"
{
    // Direct access to XMSS-Reference
    #include "randombytes.h"
}

namespace {
    TEST(XMSS_Reference, Correct_Linking) {
        unsigned char tmp[100];

        randombytes(tmp, 100);

        EXPECT_EQ(1, 1);
    }
}
