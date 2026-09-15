// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "hashing.h"
#include "misc.h"
#include "xmssBase.h"
#include "wordlist.h"
#include <crypto/secure_memory.h>
#include <crypto/system_random.h>
#include <algorithm>
#include <cctype>
#include <limits>
#include <PicoSHA2/picosha2.h>
#include <iostream>
#include <unordered_map>

std::string bin2hstr(const std::vector<unsigned char> &vec, uint32_t wrap) {
    static constexpr char HEX[] = "0123456789abcdef";
    const size_t line_breaks = wrap == 0 || vec.empty()
                                   ? 0
                                   : (vec.size() - 1) / wrap;
    std::string result;
    qrllib::secure_memory::StringWipeGuard result_guard(result);
    if (vec.size() > (std::numeric_limits<std::size_t>::max() - line_breaks) / 2) {
        throw std::length_error("hex output is too large");
    }
    result.reserve(vec.size() * 2 + line_breaks);
    size_t count = 0;
    for (const auto value : vec) {
        if (wrap > 0 && count == wrap) {
            result.push_back('\n');
            count = 0;
        }
        result.push_back(HEX[value >> 4]);
        result.push_back(HEX[value & 0x0F]);
        ++count;
    }
    result_guard.release();
    return result;
}

std::string bin2hstr(const std::string &s, uint32_t wrap) {
    static constexpr char HEX[] = "0123456789abcdef";
    const size_t line_breaks = wrap == 0 || s.empty()
                                   ? 0
                                   : (s.size() - 1) / wrap;
    std::string result;
    qrllib::secure_memory::StringWipeGuard result_guard(result);
    if (s.size() > (std::numeric_limits<std::size_t>::max() - line_breaks) / 2) {
        throw std::length_error("hex output is too large");
    }
    result.reserve(s.size() * 2 + line_breaks);
    size_t count = 0;
    for (const unsigned char value : s) {
        if (wrap > 0 && count == wrap) {
            result.push_back('\n');
            count = 0;
        }
        result.push_back(HEX[value >> 4]);
        result.push_back(HEX[value & 0x0F]);
        ++count;
    }
    result_guard.release();
    return result;
}

std::vector<unsigned char> str2bin(const std::string &s) {
    // FIXME: Avoid the copy
    return std::vector<unsigned char>(s.begin(), s.end());
}

unsigned char getHexValue(char c) {
    const auto tmp = std::tolower(static_cast<unsigned char>(c));
    if (std::isdigit(tmp)) {
        return (unsigned char) (tmp - '0');
    }
    return (unsigned char) (tmp - 'a' + 10);
}

std::vector<unsigned char> hstr2bin(const std::string &s) {
    if (s.size() % 2 != 0) {
        throw std::invalid_argument("hex string is expected to have an even number of characters");
    }

    std::vector<unsigned char> result;
    qrllib::secure_memory::WipeGuard<unsigned char> result_guard(result);
    result.reserve(s.size() / 2);
    for (std::size_t i = 0; i < s.size(); i += 2) {
        if (!std::isxdigit(static_cast<unsigned char>(s[i])) ||
            !std::isxdigit(static_cast<unsigned char>(s[i + 1]))) {
            throw std::invalid_argument("invalid hex digits in the string");
        }

        auto v = (getHexValue(s[i]) << 4) + getHexValue(s[i + 1]);
        result.push_back(v);
    }

    result_guard.release();
    return result;
}

std::string bin2mnemonic(const std::vector<unsigned char> &vec)
{
    if (vec.size() % 3 != 0) {
        throw std::invalid_argument("byte count needs to be a multiple of 3");
    }
    if (vec.size() > std::numeric_limits<std::size_t>::max() / 2) {
        throw std::length_error("mnemonic input is too large");
    }

    size_t result_size = 0;
    for (std::size_t nibble = 0; nibble < vec.size() * 2; nibble += 3) {
        const std::size_t p = nibble >> 1;
        const int b1 = vec[p];
        const int b2 = p + 1 < vec.size() ? vec[p + 1] : 0;
        const int idx = nibble % 2 == 0
                            ? (b1 << 4) + (b2 >> 4)
                            : ((b1 & 0x0F) << 8) + b2;
        const auto separator_size = nibble == 0 ? 0U : 1U;
        const auto maximum = std::numeric_limits<std::size_t>::max();
        if (result_size > maximum - separator_size ||
            wordlist[idx].size() > maximum - result_size - separator_size) {
            throw std::length_error("mnemonic output is too large");
        }
        result_size += wordlist[idx].size() + separator_size;
    }

    std::string result;
    qrllib::secure_memory::StringWipeGuard result_guard(result);
    result.reserve(result_size);
    bool first = true;
    for (std::size_t nibble = 0; nibble < vec.size() * 2; nibble += 3) {
        const std::size_t p = nibble >> 1;
        int b1 = vec[p];
        int b2 = p + 1 < vec.size() ? vec[p + 1] : 0;
        int idx = nibble % 2 == 0 ? (b1 << 4) + (b2 >> 4) : ((b1 & 0x0F) << 8) + b2;
        if (!first) {
            result.push_back(' ');
        }
        result.append(wordlist[idx]);
        first = false;
    }

    result_guard.release();
    return result;
}

std::vector<unsigned char> mnemonic2bin(const std::string &mnemonic)
{
    std::size_t word_count = 0;
    bool inside_word = false;
    for (const unsigned char character : mnemonic) {
        if (std::isspace(character)) {
            inside_word = false;
        }
        else if (!inside_word) {
            ++word_count;
            inside_word = true;
        }
    }
    if (word_count % 2 != 0)
    {
        throw std::invalid_argument("word count = " + std::to_string(word_count) + " must be even ");
    }

    // Prepare lookup
    // FIXME: Create the look up in advance
    std::unordered_map<std::string, int> word_lookup;
    int count = 0;
    for (auto &w: wordlist) {
        word_lookup[w] = count++;
    }

    std::vector<unsigned char> result;
    qrllib::secure_memory::WipeGuard<unsigned char> result_guard(result);
    if (word_count / 2 > std::numeric_limits<std::size_t>::max() / 3) {
        throw std::length_error("mnemonic input is too large");
    }
    // Count with the same whitespace rules as the parser so this allocation
    // cannot grow after decoded seed bytes have been written.
    result.reserve((word_count / 2) * 3);

    int current = 0;
    qrllib::secure_memory::RangeWipeGuard current_guard(&current, sizeof(current));
    int buffering = 0;
    qrllib::secure_memory::RangeWipeGuard buffering_guard(&buffering, sizeof(buffering));

    size_t cursor = 0;
    while (cursor < mnemonic.size()) {
        while (cursor < mnemonic.size() &&
               std::isspace(static_cast<unsigned char>(mnemonic[cursor]))) {
            ++cursor;
        }
        if (cursor == mnemonic.size()) {
            break;
        }
        const size_t start = cursor;
        while (cursor < mnemonic.size() &&
               !std::isspace(static_cast<unsigned char>(mnemonic[cursor]))) {
            ++cursor;
        }
        std::string word(mnemonic, start, cursor - start);
        qrllib::secure_memory::StringWipeGuard word_guard(word);
        auto it = word_lookup.find(word);
        if (it == word_lookup.end()) {
            throw std::invalid_argument("invalid word in mnemonic");
        }

        buffering += 3;
        current = (current << 12) + it->second;

        while (buffering > 2) {
            const int shift = 4 * (buffering - 2);
            const int mask = (1 << shift) - 1;
            int tmp = current >> shift;
            buffering -= 2;
            current &= mask;
            result.push_back((unsigned char) tmp);
        }
    }

    if (buffering > 0) {
        result.push_back((unsigned char) (current & 0xFF));
    }

    result_guard.release();
    return result;
}

std::vector<unsigned char> getRandomSeed(uint32_t seed_size, const std::string &entropy) {
#if defined(__EMSCRIPTEN__)
    (void)seed_size;
    (void)entropy;
    throw std::runtime_error(
        "native entropy is unavailable in WebAssembly; use the WebCrypto helper");
#else
    if (entropy.size() > std::numeric_limits<size_t>::max() - seed_size) {
        throw std::length_error("entropy input is too large");
    }
    std::vector<unsigned char> tmp(seed_size + entropy.size(), 0);
    qrllib::secure_memory::WipeGuard<unsigned char> tmp_guard(tmp);

    if (qrllib_system_random(tmp.data(), seed_size) != 0) {
        throw std::runtime_error("secure random generation failed");
    }

    std::copy(entropy.begin(), entropy.end(), tmp.begin() + seed_size);

    return shake256(seed_size, tmp);
#endif
}

std::vector<std::vector<unsigned char>> getHashChainSeed(const std::vector<unsigned char> &seed,
                                                         uint32_t seed_shift,
                                                         uint32_t count) {
    std::vector<std::vector<unsigned char>> result;
    qrllib::secure_memory::WipeGuard<std::vector<unsigned char>> result_guard(result);
    result.reserve(count);
    if (seed.size() > std::numeric_limits<size_t>::max() - sizeof(uint32_t) * 2) {
        throw std::length_error("hash-chain seed is too large");
    }
    std::vector<unsigned char> tmp_seed(seed.size() + sizeof(uint32_t) * 2, 0);
    qrllib::secure_memory::WipeGuard<unsigned char> tmp_seed_guard(tmp_seed);
    std::copy(seed.begin(), seed.end(), tmp_seed.begin());

    auto p = seed.size();
    for (int j = 0; j < sizeof(uint32_t); j++) {
        tmp_seed[p + j] = static_cast<unsigned char>((seed_shift >> (8 * j)) & 0xFF);
    }

    p += sizeof(uint32_t);
    for (uint32_t i = 0; i < count; i++) {
        // Apply i to the seed
        for (int j = 0; j < sizeof(uint32_t); j++) {
            tmp_seed[p + j] = static_cast<unsigned char>((i >> (8 * j)) & 0xFF);
        }

        // shake and add to result
        result.push_back(shake256(32, tmp_seed));
    }

    result_guard.release();
    return result;
}
