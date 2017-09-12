// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "misc.h"
#include <sstream>
#include <iomanip>
#include <fips202.h>
#include <randombytes.h>

std::string vec2hexstr(const std::vector<unsigned char> &vec, int wrap)
{
    std::stringstream ss;

    int count = 0;
    for(auto val : vec)
    {
        if (wrap>0)
        {
            count++;
            if (count>wrap)
            {
                ss << "\n";
                count = 1;
            }
        }
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)val;
    }

    return ss.str();
}

std::string vec2hexstr(const std::vector<char> &vec, int wrap)
{
    std::stringstream ss;

    int count = 0;
    for(auto val : vec)
    {
        if (wrap>0)
        {
            count++;
            if (count>wrap)
            {
                ss << "\n";
                count = 1;
            }
        }
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)val;
    }

    return ss.str();
}

std::string getAddress(const std::string &prefix, Xmss xmss)
{
    std::vector<unsigned char> key = xmss.getPK();
    return getAddress(prefix, key);
}

std::string getAddress(const std::string &prefix, std::vector<unsigned char> key)
{
    TKEY hashed_key(ADDRESS_HASH_SIZE, 0);
    TKEY hashed_key2(ADDRESS_HASH_SIZE, 0);

    shake256(hashed_key.data(), ADDRESS_HASH_SIZE, key.data(), key.size());
    shake256(hashed_key2.data(), ADDRESS_HASH_SIZE, hashed_key.data(), ADDRESS_HASH_SIZE);

    std::stringstream ss;
    ss << prefix;
    ss << vec2hexstr(hashed_key);
    ss << vec2hexstr(TKEY(hashed_key2.end()-4, hashed_key2.end()) );        // FIXME: Move to GSL

    return ss.str();
}

std::vector<unsigned char> tobin(const std::string &s)
{
    // FIXME: Avoid the copy
    std::vector<unsigned char> v(s.begin(), s.end());
    return v;
}

std::vector<unsigned char> getRandomSeed(uint32_t seed_size)
{
    std::vector<unsigned char> tmp(seed_size, 0);
    randombytes(tmp.data(), seed_size);
    return tmp;
}
