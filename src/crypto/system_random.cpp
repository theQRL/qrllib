// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "system_random.h"

#include "secure_memory.h"

#include <cerrno>
#include <cstddef>
#include <limits>
#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define QRLLIB_SYSTEM_RANDOM_MAX_CHUNK 1048576U

#ifndef QRLLIB_SYSTEM_RANDOM_MAX_EINTR_RETRIES
#define QRLLIB_SYSTEM_RANDOM_MAX_EINTR_RETRIES 16U
#endif

#ifndef QRLLIB_SYSTEM_RANDOM_OPEN
#define QRLLIB_SYSTEM_RANDOM_OPEN(path, flags) open((path), (flags))
#endif

#ifndef QRLLIB_SYSTEM_RANDOM_READ
#define QRLLIB_SYSTEM_RANDOM_READ(fd, buffer, length) \
    read((fd), (buffer), (length))
#endif

#ifndef QRLLIB_SYSTEM_RANDOM_CLOSE
#define QRLLIB_SYSTEM_RANDOM_CLOSE(fd) close((fd))
#endif

#if defined(QRLLIB_SYSTEM_RANDOM_TESTING)
ssize_t qrllib_system_random_test_getrandom(unsigned char* buffer,
                                            std::size_t length,
                                            unsigned int flags);
#define QRLLIB_SYSTEM_RANDOM_GETRANDOM(buffer, length, flags) \
    qrllib_system_random_test_getrandom((buffer), (length), (flags))
#elif defined(SYS_getrandom) && !defined(QRLLIB_SYSTEM_RANDOM_GETRANDOM)
#define QRLLIB_SYSTEM_RANDOM_GETRANDOM(buffer, length, flags) \
    syscall(SYS_getrandom, (buffer), (length), (flags))
#endif

namespace {

thread_local unsigned int entropy_operation_depth = 0;
thread_local bool entropy_operation_failed = false;

#if defined(__EMSCRIPTEN__)

// WebCrypto limits getRandomValues() to 65,536 bytes per call. Keep the
// platform bridge here, rather than relying on Emscripten's virtual
// /dev/urandom, so an unavailable or throwing entropy source becomes a
// status that the public adapters can handle and wipe.
EM_JS(int, qrllib_web_crypto_random,
      (unsigned char* output, std::size_t length), {
    try {
        output = output >>> 0;
        length = length >>> 0;
        if (length === 0) {
            return 0;
        }
        if (output === 0 || output > HEAPU8.length ||
            length > HEAPU8.length - output) {
            return -1;
        }

        var cryptoObject =
            (typeof globalThis !== 'undefined' && globalThis.crypto) ||
            (typeof self !== 'undefined' && self.crypto) ||
            (typeof window !== 'undefined' && window.crypto);
        var fill = null;

        if (cryptoObject &&
            typeof cryptoObject.getRandomValues === 'function') {
            fill = function(view) {
                if (typeof SharedArrayBuffer !== 'undefined' &&
                    view.buffer instanceof SharedArrayBuffer) {
                    var temporary = new Uint8Array(view.byteLength);
                    try {
                        cryptoObject.getRandomValues(temporary);
                        view.set(temporary);
                    } finally {
                        temporary.fill(0);
                    }
                    return;
                }
                cryptoObject.getRandomValues(view);
            };
        } else if (typeof process !== 'undefined' && process.versions &&
                   process.versions.node && typeof require === 'function') {
            // Node versions predating global WebCrypto still provide a
            // cryptographically secure random source through node:crypto.
            var nodeCrypto = require('crypto');
            if (typeof nodeCrypto.randomFillSync === 'function') {
                fill = function(view) {
                    nodeCrypto.randomFillSync(view);
                };
            } else if (typeof nodeCrypto.randomBytes === 'function') {
                fill = function(view) {
                    var temporary = nodeCrypto.randomBytes(view.byteLength);
                    try {
                        view.set(temporary);
                    } finally {
                        temporary.fill(0);
                    }
                };
            }
        }

        if (fill === null) {
            return -1;
        }

        var maximumRequest = 65536;
        for (var offset = 0; offset < length; offset += maximumRequest) {
            var request = Math.min(maximumRequest, length - offset);
            fill(HEAPU8.subarray(output + offset,
                                 output + offset + request));
        }
        return 0;
    } catch (error) {
        return -1;
    }
});

int fill_system_random(unsigned char* output, std::size_t length) noexcept
{
    return qrllib_web_crypto_random(output, length);
}

#elif defined(_WIN32)

int fill_system_random(unsigned char* output, std::size_t length) noexcept
{
    while (length != 0) {
        const auto maximum =
            static_cast<std::size_t>(std::numeric_limits<ULONG>::max());
        const ULONG request = static_cast<ULONG>(
            length < maximum ? length : maximum);
        const NTSTATUS status = BCryptGenRandom(nullptr,
                                                output,
                                                request,
                                                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            return -1;
        }
        output += request;
        length -= request;
    }
    return 0;
}

#else

int fill_from_urandom(unsigned char* output, std::size_t length) noexcept
{
    int random_fd = -1;
    unsigned int interrupted = 0;

    for (;;) {
        random_fd = QRLLIB_SYSTEM_RANDOM_OPEN("/dev/urandom", O_RDONLY);
        if (random_fd != -1) {
            break;
        }
        if (errno != EINTR ||
            interrupted >= QRLLIB_SYSTEM_RANDOM_MAX_EINTR_RETRIES) {
            return -1;
        }
        ++interrupted;
    }

    interrupted = 0;
    while (length > 0) {
        const std::size_t request =
            length < QRLLIB_SYSTEM_RANDOM_MAX_CHUNK
                ? length
                : QRLLIB_SYSTEM_RANDOM_MAX_CHUNK;
        const ssize_t received = QRLLIB_SYSTEM_RANDOM_READ(random_fd,
                                                           output,
                                                           request);

        if (received > 0) {
            if (static_cast<std::size_t>(received) > request) {
                (void)QRLLIB_SYSTEM_RANDOM_CLOSE(random_fd);
                return -1;
            }
            output += static_cast<std::size_t>(received);
            length -= static_cast<std::size_t>(received);
            interrupted = 0;
            continue;
        }

        if (received < 0 && errno == EINTR &&
            interrupted < QRLLIB_SYSTEM_RANDOM_MAX_EINTR_RETRIES) {
            ++interrupted;
            continue;
        }

        (void)QRLLIB_SYSTEM_RANDOM_CLOSE(random_fd);
        return -1;
    }

    (void)QRLLIB_SYSTEM_RANDOM_CLOSE(random_fd);
    return 0;
}

int fill_system_random(unsigned char* output, std::size_t length) noexcept
{
#ifdef QRLLIB_SYSTEM_RANDOM_GETRANDOM
    unsigned int interrupted = 0;

    while (length > 0) {
        const std::size_t request =
            length < QRLLIB_SYSTEM_RANDOM_MAX_CHUNK
                ? length
                : QRLLIB_SYSTEM_RANDOM_MAX_CHUNK;
        const ssize_t received = static_cast<ssize_t>(
            QRLLIB_SYSTEM_RANDOM_GETRANDOM(output, request, 0));

        if (received > 0) {
            if (static_cast<std::size_t>(received) > request) {
                return -1;
            }
            output += static_cast<std::size_t>(received);
            length -= static_cast<std::size_t>(received);
            interrupted = 0;
            continue;
        }

        if (received < 0 && errno == EINTR &&
            interrupted < QRLLIB_SYSTEM_RANDOM_MAX_EINTR_RETRIES) {
            ++interrupted;
            continue;
        }

        if (received < 0 && errno == ENOSYS) {
            return fill_from_urandom(output, length);
        }

        return -1;
    }

    return 0;
#else
    return fill_from_urandom(output, length);
#endif
}

#endif

}  // namespace

int qrllib_system_random(unsigned char* output, std::size_t length) noexcept
{
    if (length == 0) {
        return 0;
    }
    if (output == nullptr) {
        return -1;
    }
    if (fill_system_random(output, length) == 0) {
        return 0;
    }

    qrllib::secure_memory::secure_zero(output, length);
    return -1;
}

void qrllib_entropy_operation_begin() noexcept
{
    if (entropy_operation_depth == 0) {
        entropy_operation_failed = false;
    }
    ++entropy_operation_depth;
}

int qrllib_entropy_operation_end() noexcept
{
    if (entropy_operation_depth == 0) {
        return -1;
    }

    const bool failed = entropy_operation_failed;
    --entropy_operation_depth;
    if (entropy_operation_depth == 0) {
        entropy_operation_failed = false;
    }
    return failed ? -1 : 0;
}

void randombytes(unsigned char* output, std::size_t length)
{
    if (qrllib_system_random(output, length) != 0) {
        entropy_operation_failed = true;
    }
}
