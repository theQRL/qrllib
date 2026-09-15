// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_SECURE_ALLOCATOR_H
#define QRLLIB_SECURE_ALLOCATOR_H

#include <cstddef>
#include <limits>
#include <memory>
#include <type_traits>
#include <vector>

#include "secure_memory.h"

namespace qrllib {
namespace secure_memory {

// Building block for the next versioned API. Existing public/protected vector
// fields deliberately retain std::allocator so this patch does not change
// their concrete type or class layout.
template<typename T>
class SecureAllocator {
public:
    using value_type = T;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::true_type;

    SecureAllocator() noexcept = default;

    template<typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept
    {
    }

    T* allocate(std::size_t count)
    {
        if (count > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            throw std::bad_array_new_length();
        }
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* data, std::size_t count) noexcept
    {
        if (count != 0) {
            secure_zero(data, count * sizeof(T));
        }
        std::allocator<T>{}.deallocate(data, count);
    }
};

template<typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept
{
    return true;
}

template<typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept
{
    return false;
}

template<typename T>
using SecureVector = std::vector<T, SecureAllocator<T>>;

}  // namespace secure_memory
}  // namespace qrllib

#endif  // QRLLIB_SECURE_ALLOCATOR_H
