// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "misc.h"
#include "xmssBase.h"
#include <sstream>
#include <iomanip>
#include <fips202.h>
#include <picosha2.h>
#include <randombytes.h>
#include <iostream>
#include <unordered_map>

std::string bin2hstr(const std::vector<unsigned char> &vec, int wrap)
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

std::string bin2hstr(const std::string &s, int wrap)
{
    return bin2hstr(str2bin(s), wrap);
}

std::vector<unsigned char> str2bin(const std::string &s)
{
    // FIXME: Avoid the copy
    return std::vector<unsigned char>(s.begin(), s.end());
}

unsigned char getHexValue(char c)
{
    auto tmp = std::tolower(c);
    if (std::isdigit(tmp))
    {
        return (unsigned char)(tmp-'0');
    }
    return (unsigned char)(tmp-'a'+10);
}

std::vector<unsigned char> hstr2bin(const std::string &s) throw(std::invalid_argument)
{
    if (s.size()%2!=0)
    {
        throw std::invalid_argument("hex string is expected to have an even number of characters");
    }

    std::vector<unsigned char> result;
    for(int i=0; i<s.size(); i+=2)
    {
        if ( !std::isxdigit(s[i]) || !std::isxdigit(s[i+1]) )
        {
            throw std::invalid_argument("invalid hex digits in the string");
        }

        auto v = (getHexValue(s[i])<<4) + getHexValue(s[i+1]);
        result.push_back(v);
    }

    return result;
}

std::string bin2mnemonic(const std::vector<unsigned char> &vec, const std::vector<std::string> &word_list)
{
    size_t num_words = word_list.size();
    if (num_words != 4096)
    {
        throw std::invalid_argument("word list should contain 4096 words");
    }

    std::stringstream ss;
    std::string separator;
    for(int nibble = 0; nibble < vec.size()*2; nibble+=3)
    {
        int p = nibble >> 1;
        int b1 = vec[p];
        int b2 = p+1<vec.size() ? vec[p+1] : 0;
        int idx = nibble%2==0 ? (b1 << 4) + (b2 >> 4) : ((b1 & 0x0F) << 8) + b2;
        //std::cout << nibble << " " << p << " " << std::hex <<  idx << std::endl;
        ss << separator << word_list[idx];
        separator = " ";
    }

    return ss.str();
}

std::vector<unsigned char> mnemonic2bin(const std::string &mnemonic, const std::vector<std::string> &word_list)
{
    size_t num_words = word_list.size();
    if (num_words != 4096)
    {
        throw std::invalid_argument("word list should contain 4096 words");
    }

    // Prepare lookup
    std::unordered_map<std::string, int> word_lookup;
    int count = 0;
    for (auto &w: word_list)
    {
        word_lookup[w]=count++;
    }

    std::stringstream ss(mnemonic);
    std::string word;

    std::vector<unsigned char> result;

    int current = 0;
    int buffering = 0;

    while(ss >> word)
    {
        auto it = word_lookup.find(word);
        if (it==word_lookup.end())
        {
            throw std::invalid_argument("invalid word in mnemonic");
        }

        buffering += 3;
        current = (current<<12)+ it->second;

        while(buffering>2)
        {
            const int shift = 4*(buffering-2);
            const int mask = (1 << shift)-1;
            int tmp = current >> shift;
            buffering-=2;
            current &= mask;
            result.push_back( (unsigned char)tmp);
        }
    }

    if (buffering>0)
    {
        result.push_back( (unsigned char) (current&0xFF));
    }

    return result;
}

std::vector<unsigned char> shake128(size_t hash_size, std::vector<unsigned char> input)
{
    std::vector<unsigned char> hashed_output(hash_size, 0);
    shake128(hashed_output.data(), hash_size, input.data(), input.size() );
    return hashed_output;
}

std::vector<unsigned char> shake256(size_t hash_size, std::vector<unsigned char> input)
{
    std::vector<unsigned char> hashed_output(hash_size, 0);
    shake256(hashed_output.data(), hash_size, input.data(), input.size() );
    return hashed_output;
}

std::vector<unsigned char> sha2_256(std::vector<unsigned char> input)
{
    std::vector<unsigned char> hashed_output(32, 0);
    picosha2::hash256( input.begin(), input.end(), hashed_output.begin(), hashed_output.end() );
    return hashed_output;
}

std::string getAddress(const std::string &prefix, std::vector<unsigned char> &key)
{
    TKEY hashed_key(ADDRESS_HASH_SIZE, 0);
    TKEY hashed_key2(ADDRESS_HASH_SIZE, 0);

    picosha2::hash256( key.begin(), key.end(), hashed_key.begin(), hashed_key.end() );
    picosha2::hash256( hashed_key.begin(), hashed_key.end(), hashed_key2.begin(), hashed_key2.end() );

    std::stringstream ss;
    ss << prefix;
    ss << bin2hstr(hashed_key);
    ss << bin2hstr(TKEY(hashed_key2.end() - 4, hashed_key2.end()));        // FIXME: Move to GSL

    return ss.str();
}

std::vector<unsigned char> getRandomSeed(uint32_t seed_size, const std::string &entropy)
{
    auto tmpbytes = str2bin(entropy);
    std::vector<unsigned char> tmp(seed_size, 0);

    tmp.insert( tmp.end(), tmpbytes.begin(), tmpbytes.end());
    randombytes(tmp.data(), seed_size);

    return shake256(seed_size, tmp);
}

std::vector<std::vector<unsigned char>> getHashChainSeed(const std::vector<unsigned char> &seed,
                                                         uint32_t seed_shift,
                                                         uint32_t count)
{
    std::vector<std::vector<unsigned char>> result;
    std::vector<unsigned char> tmp_seed(seed);
    tmp_seed.resize(seed.size() + sizeof(uint32_t) * 2, 0);

    auto p = seed.size();
    for(int j=0; j<sizeof(uint32_t); j++)
    {
        tmp_seed[p+j]= static_cast<unsigned char>((seed_shift >> (8*j)) & 0xFF);
    }

    p+=sizeof(uint32_t);
    for(uint32_t i=0; i<count; i++)
    {
        // Apply i to the seed
        for(int j=0; j<sizeof(uint32_t); j++)
        {
            tmp_seed[p+j]= static_cast<unsigned char>((i >> (8*j)) & 0xFF);
        }

        // shake and add to result
        result.push_back(shake256(32, tmp_seed));
    }

    return result;
}
