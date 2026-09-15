// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_SECURE_MEMORY_H
#define QRLLIB_SECURE_MEMORY_H

#include <cstddef>
#include <exception>
#include <limits>
#include <string>
#include <type_traits>
#include <vector>

namespace qrllib {
namespace secure_memory {

// Erases a live writable range using stores that the compiler may not elide.
// A null pointer is accepted only for a zero-length range.
void secure_zero(void* data, std::size_t size) noexcept;

class RangeWipeGuard {
public:
    RangeWipeGuard(void* data, std::size_t size) noexcept
        : _data(data), _size(size) {}
    RangeWipeGuard(const RangeWipeGuard&) = delete;
    RangeWipeGuard& operator=(const RangeWipeGuard&) = delete;
    ~RangeWipeGuard() { secure_zero(_data, _size); }
    void release() noexcept
    {
        _data = nullptr;
        _size = 0;
    }

private:
    void* _data;
    std::size_t _size;
};

template<typename T>
void wipe(std::vector<T>& value) noexcept
{
    static_assert(std::is_trivially_copyable<T>::value,
                  "secure_memory::wipe requires trivially copyable elements");
    static_assert(std::is_nothrow_default_constructible<T>::value,
                  "secure_memory::wipe requires no-throw value construction");

    // A caller (including a derived class with protected access) may shrink a
    // vector without erasing the discarded elements. Make the whole existing
    // allocation live before wiping it; writing directly through data() past
    // size() would be undefined and trips annotated libc++ containers under
    // AddressSanitizer.
    const std::size_t original_size = value.size();
    if (original_size < value.capacity()) {
        value.resize(value.capacity());
    }
    if (value.empty()) {
        return;
    }
    if (value.size() > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
        std::terminate();
    }
    secure_zero(value.data(), value.size() * sizeof(T));
    if (original_size < value.size()) {
        value.resize(original_size);
    }
}

template<typename T>
void wipe(std::vector<std::vector<T>>& value) noexcept
{
    for (auto& element : value) {
        wipe(element);
    }
}

inline void wipe(std::string& value) noexcept
{
    // As with vectors, cover bytes that may have been removed by a shrink but
    // still remain in the string's allocation. Growing only to the existing
    // capacity cannot reallocate.
    const std::size_t original_size = value.size();
    if (original_size < value.capacity()) {
        value.resize(value.capacity(), '\0');
    }
    if (!value.empty()) {
        secure_zero(&value[0], value.size());
    }
    if (original_size < value.size()) {
        value.resize(original_size);
    }
}

template<typename T>
class WipeGuard {
public:
    explicit WipeGuard(std::vector<T>& value) noexcept : _value(&value) {}
    WipeGuard(const WipeGuard&) = delete;
    WipeGuard& operator=(const WipeGuard&) = delete;

    ~WipeGuard()
    {
        if (_value != nullptr) {
            wipe(*_value);
        }
    }

    void release() noexcept { _value = nullptr; }

private:
    std::vector<T>* _value;
};

class StringWipeGuard {
public:
    explicit StringWipeGuard(std::string& value) noexcept : _value(&value) {}
    StringWipeGuard(const StringWipeGuard&) = delete;
    StringWipeGuard& operator=(const StringWipeGuard&) = delete;
    ~StringWipeGuard()
    {
        if (_value != nullptr) {
            wipe(*_value);
        }
    }
    void release() noexcept { _value = nullptr; }

private:
    std::string* _value;
};

template<typename T>
void wipe_and_clear(std::vector<T>& value) noexcept
{
    wipe(value);
    value.clear();
}

template<typename T>
void wipe_and_swap(std::vector<T>& destination, std::vector<T>& replacement) noexcept
{
    wipe(destination);
    destination.swap(replacement);
}

}  // namespace secure_memory
}  // namespace qrllib

#endif  // QRLLIB_SECURE_MEMORY_H
