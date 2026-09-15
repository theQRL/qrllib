// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#if defined(QRLLIB_HAVE_MEMSET_S)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "secure_memory.h"

#include <exception>

#if defined(_WIN32)
#include <windows.h>
#elif defined(QRLLIB_HAVE_EXPLICIT_BZERO) || defined(QRLLIB_HAVE_MEMSET_S)
#include <string.h>
#endif

namespace qrllib {
namespace secure_memory {

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
void secure_zero(void* data, std::size_t size) noexcept
{
    if (size == 0) {
        return;
    }
    if (data == nullptr) {
        std::terminate();
    }

#if defined(_WIN32)
    SecureZeroMemory(data, size);
#elif defined(QRLLIB_HAVE_EXPLICIT_BZERO)
    explicit_bzero(data, size);
#elif defined(QRLLIB_HAVE_MEMSET_S)
    (void)memset_s(data, size, 0, size);
#else
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (size-- != 0) {
        *cursor++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(data) : "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
#endif
}

}  // namespace secure_memory
}  // namespace qrllib
