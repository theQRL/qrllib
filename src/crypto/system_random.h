// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_SYSTEM_RANDOM_H
#define QRLLIB_SYSTEM_RANDOM_H

#include <cstddef>

// Status-returning implementation used by tests and parent-owned adapters.
int qrllib_system_random(unsigned char* output, std::size_t length) noexcept;

// The vendored reference implementations expose randombytes as void. These
// scopes turn a failure in that legacy callback into an explicit API result.
void qrllib_entropy_operation_begin() noexcept;
int qrllib_entropy_operation_end() noexcept;

// Legacy callback required by the vendored Dilithium and Kyber sources.
void randombytes(unsigned char* output, std::size_t length);

#endif  // QRLLIB_SYSTEM_RANDOM_H
