// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <cstdint>
#include <qrlHelper.h>
#include <misc.h>
#include <stdexcept>
#include "gtest/gtest.h"

namespace {
TEST(QRL_Helper, validateAddress)
{
    auto pk = QRLDescriptor(eHashFunction::SHA2_256,
                            eSignatureType::XMSS,
                            4,
                            eAddrFormatType::SHA256_2X).getBytes();
    pk.resize(QRLDescriptor::getSize()+64, 0);

    auto address = QRLHelper::getAddress(pk);


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

    EXPECT_FALSE(QRLHelper::addressIsValid(address));
}

// Regression coverage for multi-sig addresses.
//
// QRL uses signature type 1 for multi-sig addresses, giving descriptor byte
// 0x11. They have no XMSS tree behind them, so the height nibble is 0. The
// v1.3.0 descriptor hardening validated every descriptor as if it were XMSS
// and so rejected all of them, which made QRL's
// MultiSigAddressState.address_is_valid() return false for every multi-sig
// address on the network. These tests pin the behaviour in both directions:
// multi-sig descriptors are accepted, and the XMSS hardening still bites.

TEST(QRL_Helper, validateMultiSigAddress)
{
    // QRL builds multi-sig addresses from the literal descriptor "110000",
    // i.e. hash function 1 (SHAKE_128) and signature type 1.
    auto pk = QRLDescriptor(eHashFunction::SHAKE_128,
                            eSignatureType::MULTISIG,
                            0,
                            eAddrFormatType::SHA256_2X).getBytes();
    ASSERT_EQ(0x11, pk[0]);  // signature type 1 | SHAKE_128
    ASSERT_EQ(0x00, pk[1]);  // no XMSS tree, so the height nibble is zero
    pk.resize(QRLDescriptor::getSize()+64, 0);

    auto address = QRLHelper::getAddress(pk);
    EXPECT_TRUE(QRLHelper::addressIsValid(address));

    // The checksum must still be enforced for multi-sig addresses.
    auto corrupted = address;
    corrupted[address.size()-1] ^= 0xFF;
    EXPECT_FALSE(QRLHelper::addressIsValid(corrupted));

    // Tampering with the descriptor breaks the checksum, which covers it.
    auto reserved = address;
    reserved[2] = 1;
    EXPECT_FALSE(QRLHelper::addressIsValid(reserved));
}

TEST(QRL_Helper, validateMultiSigAddressGeneratedByQRL)
{
    // Produced by QRL's MultiSigAddressState.generate_multi_sig_address().
    // Valid under qrllib 1.2.4, rejected by v1.3.0 before this fix.
    const auto address = hstr2bin(
            "11000005bc07de22117e835d760a8081d91ba50eac3b4f1226bae23215ad3f5034d45ed5d5f2a7");
    ASSERT_EQ(QRLDescriptor::getSize()+ADDRESS_HASH_SIZE+4, address.size());
    EXPECT_TRUE(QRLHelper::addressIsValid(address));
}

// Regression coverage for theQRL/QRL#1816.
//
// Address validity is a consensus rule and must match v1.2.4: length, address
// format and checksum only. Token tx 7e94193f...22f1 in mainnet block 1796388
// pays a holder whose descriptor byte 0 is 0x0c (hash function 0xC). v1.2.8+
// ran the XMSS descriptor hardening inside addressIsValid() and rejected it,
// so fresh nodes could no longer sync past that block.

TEST(QRL_Helper, validateMainnetAddressWithUnknownHashFunction)
{
    const auto address = hstr2bin(
            "0c0d00e3acde5fa627b3c0f2d723108c265f16b9667a19d811b3c99ac329028ec8abf52fc5cca6");
    ASSERT_EQ(QRLDescriptor::getSize()+ADDRESS_HASH_SIZE+4, address.size());
    EXPECT_TRUE(QRLHelper::addressIsValid(address));

    auto corrupted = address;
    corrupted[address.size()-1] ^= 0xFF;
    EXPECT_FALSE(QRLHelper::addressIsValid(corrupted));
}

std::vector<uint8_t> addressWithDescriptor(const std::vector<uint8_t>& descr)
{
    // Arbitrary 32-byte hash plus a correct checksum over descriptor + hash.
    auto address = descr;
    address.resize(QRLDescriptor::getSize()+ADDRESS_HASH_SIZE, 0xAB);

    std::vector<uint8_t> checksum(ADDRESS_HASH_SIZE, 0);
    picosha2::hash256(address.cbegin(), address.cend(), checksum.begin(), checksum.end());
    address.insert(address.end(), checksum.cend()-4, checksum.cend());
    return address;
}

TEST(QRL_Helper, addressValidityIgnoresDescriptorFieldsOtherThanFormat)
{
    // None of these are well-formed XMSS descriptors, but v1.2.4 accepted
    // all of them, so addressIsValid() must too.
    EXPECT_TRUE(QRLHelper::addressIsValid(addressWithDescriptor({0x0c, 0x0d, 0x00})));  // hash fn 0xC
    EXPECT_TRUE(QRLHelper::addressIsValid(addressWithDescriptor({0x21, 0x00, 0x00})));  // sig type 2
    EXPECT_TRUE(QRLHelper::addressIsValid(addressWithDescriptor({0x00, 0x00, 0x00})));  // height 0
    EXPECT_TRUE(QRLHelper::addressIsValid(addressWithDescriptor({0x00, 0x02, 0x01})));  // reserved byte

    // The address format is still enforced.
    EXPECT_FALSE(QRLHelper::addressIsValid(addressWithDescriptor({0x00, 0x12, 0x00})));
}

TEST(QRL_Helper, multiSigDescriptorRoundTrips)
{
    const auto descr = QRLDescriptor::fromBytes({0x11, 0x00, 0x00});
    EXPECT_EQ(eSignatureType::MULTISIG, descr.getSignatureType());
    EXPECT_EQ(eHashFunction::SHAKE_128, descr.getHashFunction());
    EXPECT_EQ(0, descr.getHeight());
    EXPECT_EQ(eAddrFormatType::SHA256_2X, descr.getAddrFormatType());
}

TEST(QRL_Helper, rejectsMultiSigDescriptorWithTreeHeight)
{
    // A multi-sig descriptor carries no tree, so a non-zero height is malformed.
    EXPECT_THROW(QRLDescriptor::fromBytes({0x11, 0x02, 0x00}), std::invalid_argument);
    EXPECT_THROW(QRLDescriptor(eHashFunction::SHAKE_128,
                               eSignatureType::MULTISIG,
                               4,
                               eAddrFormatType::SHA256_2X),
                 std::invalid_argument);
}

TEST(QRL_Helper, xmssHardeningStillApplies)
{
    // Unknown signature types stay rejected.
    EXPECT_THROW(QRLDescriptor::fromBytes({0x21, 0x00, 0x00}), std::invalid_argument);

    // XMSS heights must still be even and within range.
    EXPECT_THROW(QRLDescriptor(eHashFunction::SHA2_256,
                               eSignatureType::XMSS,
                               0,
                               eAddrFormatType::SHA256_2X),
                 std::invalid_argument);
    EXPECT_THROW(QRLDescriptor(eHashFunction::SHA2_256,
                               eSignatureType::XMSS,
                               5,
                               eAddrFormatType::SHA256_2X),
                 std::invalid_argument);

    // The reserved descriptor byte must still be zero.
    EXPECT_THROW(QRLDescriptor::fromBytes({0x11, 0x00, 0x01}), std::invalid_argument);
}
}
