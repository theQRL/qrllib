// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_MISC_H
#define QRLLIB_MISC_H

#include<string>
#include<vector>
#include "xmss.h"

#define ADDRESS_HASH_SIZE 32

std::string vec2hexstr(const std::vector<unsigned char> &vec, int wrap = 0);
std::string vec2hexstr(const std::vector<char> &vec, int wrap = 0);

std::string getAddress(const std::string &prefix, Xmss xmss);
std::string getAddress(const std::string &prefix, std::vector<unsigned char> key);

std::vector<unsigned char> tobin(const std::string &s);

std::vector<unsigned char> getRandomSeed(uint32_t seed_size);

#endif //QRLLIB_MISC_H
