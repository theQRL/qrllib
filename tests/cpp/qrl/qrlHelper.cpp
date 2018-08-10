// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <cstdint>
#include <qrlHelper.h>
#include "gtest/gtest.h"

namespace {
TEST(QRL_Helper, validateAddress)
{
    std::vector<unsigned char> pk(QRLDescriptor::getSize()+64, 0);

    auto address = QRLHelper::getAddress(pk);

    std::cout << std::endl;
    std::cout << bin2hstr(address) << std::endl;

    EXPECT_TRUE(QRLHelper::addressIsValid(address));

    auto address2 = address;
    address2[2] = 23;
    EXPECT_FALSE(QRLHelper::addressIsValid(address2));

    address2 = address;
    EXPECT_TRUE(QRLHelper::addressIsValid(address2));

    address2[1] = 1;
    EXPECT_FALSE(QRLHelper::addressIsValid(address2));
}

TEST(QRL_Helper, validateAddressEmpty)
{
    auto address = std::vector<uint8_t>();
    std::cout << std::endl;
    std::cout << bin2hstr(address) << std::endl;

    EXPECT_FALSE(QRLHelper::addressIsValid(address));
}
}
