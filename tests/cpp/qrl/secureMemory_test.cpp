// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <array>
#include <cstdint>
#include <vector>

#include <crypto/secure_memory.h>
#include <crypto/secure_allocator.h>
#include "gtest/gtest.h"

namespace {

struct StickyByte {
    uint8_t value;
    StickyByte() noexcept {}
};

static_assert(std::is_trivially_copyable<StickyByte>::value,
              "test byte must be eligible for secure_memory::wipe");

TEST(SecureMemory, ZeroLengthAcceptsNull)
{
    EXPECT_NO_THROW(qrllib::secure_memory::secure_zero(nullptr, 0));
}

TEST(SecureMemory, ErasesExactlyTheRequestedRange)
{
    std::array<uint8_t, 10> bytes{};
    bytes.fill(0x5a);

    qrllib::secure_memory::secure_zero(bytes.data() + 2, 6);

    EXPECT_EQ(0x5a, bytes[0]);
    EXPECT_EQ(0x5a, bytes[1]);
    for (size_t i = 2; i < 8; ++i) {
        EXPECT_EQ(0, bytes[i]);
    }
    EXPECT_EQ(0x5a, bytes[8]);
    EXPECT_EQ(0x5a, bytes[9]);
}

TEST(SecureMemory, WipesDisplacedVectorBeforeReplacement)
{
    std::vector<uint8_t> current(32, 0xa5);
    std::vector<uint8_t> replacement(16, 0x3c);

    qrllib::secure_memory::wipe_and_swap(current, replacement);

    EXPECT_EQ(std::vector<uint8_t>(16, 0x3c), current);
    EXPECT_EQ(std::vector<uint8_t>(32, 0), replacement);
}

TEST(SecureMemory, SafelyCoversSpareVectorCapacity)
{
    std::vector<StickyByte> bytes;
    bytes.reserve(33);
    bytes.resize(33);
    for (auto& byte : bytes) {
        byte.value = 0xa5;
    }
    bytes.resize(32);
    const auto capacity = bytes.capacity();

    EXPECT_NO_THROW(qrllib::secure_memory::wipe(bytes));
    EXPECT_EQ(32u, bytes.size());
    EXPECT_EQ(capacity, bytes.capacity());
    bytes.resize(33);
    for (const auto& byte : bytes) {
        EXPECT_EQ(0, byte.value);
    }
}

TEST(SecureMemory, SecureAllocatorSupportsVectorMovesAndSwaps)
{
    using SecureBytes = qrllib::secure_memory::SecureVector<uint8_t>;
    static_assert(std::allocator_traits<SecureBytes::allocator_type>::
                      propagate_on_container_move_assignment::value,
                  "secure allocator must propagate on move");
    static_assert(std::allocator_traits<SecureBytes::allocator_type>::
                      propagate_on_container_swap::value,
                  "secure allocator must propagate on swap");

    SecureBytes first(32, 0x7b);
    SecureBytes second(4, 0x21);
    first.swap(second);
    EXPECT_EQ(4u, first.size());
    EXPECT_EQ(32u, second.size());

    SecureBytes moved;
    moved = std::move(second);
    EXPECT_EQ(32u, moved.size());
}

}  // namespace
