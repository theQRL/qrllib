// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_MISC_H
#define QRLLIB_MISC_H

#include<string>
#include<vector>
#include <stdexcept>

#define ADDRESS_HASH_SIZE 32

// FIXME: Move this to templates
std::string bin2hstr(const std::vector<unsigned char> &vec, uint32_t wrap = 0);
std::string bin2hstr(const std::string &vec, uint32_t wrap = 0);
std::vector<unsigned char> str2bin(const std::string &s);
std::vector<unsigned char> hstr2bin(const std::string &s) throw(std::invalid_argument);

std::string bin2mnemonic(const std::vector<unsigned char> &vec, const std::vector<std::string> &word_list);
std::vector<unsigned char> mnemonic2bin(const std::string &mnemonic, const std::vector<std::string> &word_list);

std::vector<unsigned char> sha2_256(std::vector<unsigned char> input);
std::vector<unsigned char> shake128(size_t hash_size, std::vector<unsigned char> input);
std::vector<unsigned char> shake256(size_t hash_size, std::vector<unsigned char> data);

std::vector<unsigned char> getRandomSeed(uint32_t seed_size, const std::string &entropy);

std::string getAddress(const std::string &prefix, const std::vector<unsigned char> &key);

std::vector<std::vector<unsigned char>> getHashChainSeed(const std::vector<unsigned char> &seed, uint32_t seed_shift, uint32_t count);

#endif //QRLLIB_MISC_H
