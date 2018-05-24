// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "hashing.h"
#include "misc.h"
#include "xmssBase.h"
#include "wordlist.h"
#include <sstream>
#include <iomanip>
#include <PicoSHA2/picosha2.h>
#include <iostream>
#include <unordered_map>
#include <fstream>

std::string bin2hstr(const std::vector<unsigned char> &vec, uint32_t wrap) {
    std::stringstream ss;

    int count = 0;
    for (auto val : vec) {
        if (wrap > 0) {
            count++;
            if (count > wrap) {
                ss << "\n";
                count = 1;
            }
        }
        ss << std::setfill('0') << std::setw(2) << std::hex << (int) val;
    }

    return ss.str();
}

std::string bin2hstr(const std::string &s, uint32_t wrap) {
    return bin2hstr(str2bin(s), wrap);
}

std::vector<unsigned char> str2bin(const std::string &s) {
    // FIXME: Avoid the copy
    return std::vector<unsigned char>(s.begin(), s.end());
}

unsigned char getHexValue(char c) {
    auto tmp = std::tolower(c);
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
    for (int i = 0; i < s.size(); i += 2) {
        if (!std::isxdigit(s[i]) || !std::isxdigit(s[i + 1])) {
            throw std::invalid_argument("invalid hex digits in the string");
        }

        auto v = (getHexValue(s[i]) << 4) + getHexValue(s[i + 1]);
        result.push_back(v);
    }

    return result;
}

std::string bin2mnemonic(const std::vector<unsigned char> &vec)
{
    if (vec.size() % 3 != 0) {
        throw std::invalid_argument("byte count needs to be a multiple of 3");
    }

    std::stringstream ss;
    std::string separator;
    for (int nibble = 0; nibble < vec.size() * 2; nibble += 3) {
        int p = nibble >> 1;
        int b1 = vec[p];
        int b2 = p + 1 < vec.size() ? vec[p + 1] : 0;
        int idx = nibble % 2 == 0 ? (b1 << 4) + (b2 >> 4) : ((b1 & 0x0F) << 8) + b2;
        ss << separator << wordlist[idx];
        separator = " ";
    }

    return ss.str();
}

std::vector<unsigned char> mnemonic2bin(const std::string &mnemonic)
{
    auto word_count = std::count(mnemonic.cbegin(), mnemonic.cend(), ' ') + 1;
    if (word_count%2!=0)
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

    std::stringstream ss(mnemonic);
    std::string word;

    std::vector<unsigned char> result;

    int current = 0;
    int buffering = 0;

    while (ss >> word) {
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

    return result;
}

std::vector<unsigned char> getRandomSeed(uint32_t seed_size, const std::string &entropy) {
    std::vector<unsigned char> tmp(seed_size, 0);

    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom) {
        throw std::runtime_error("error accessing /dev/urandom");
    }

    urandom.read(reinterpret_cast<char *>(tmp.data()), seed_size);
    if (!urandom) {
        throw std::runtime_error("error reading from /dev/urandom");
    }
    urandom.close();

    auto tmpbytes = str2bin(entropy);
    tmp.insert(tmp.end(), tmpbytes.begin(), tmpbytes.end());

    return shake256(seed_size, tmp);
}

std::vector<std::vector<unsigned char>> getHashChainSeed(const std::vector<unsigned char> &seed,
                                                         uint32_t seed_shift,
                                                         uint32_t count) {
    std::vector<std::vector<unsigned char>> result;
    std::vector<unsigned char> tmp_seed(seed);
    tmp_seed.resize(seed.size() + sizeof(uint32_t) * 2, 0);

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

    return result;
}
