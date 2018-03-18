#include <exception>
#include <system_error>
#include <cassert>
#include <vector>

#ifdef _WIN32
#include <wtypesbase.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <fstream>
#endif

std::vector<unsigned char> shake256(size_t hash_size, std::vector<unsigned char> input);

extern "C" {
  bool randombytes(unsigned char *x, const size_t xlen)
  {
#ifdef _WIN32
      return BCryptGenRandom(nullptr, x, static_cast<ULONG>(xlen), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
#else
     std::ifstream urandom("/dev/urandom", std::ios::binary);
     if(urandom)
       urandom.read(reinterpret_cast<char*>(x), xlen);
  
     return urandom.good();
#endif
  }
}

std::system_error last_error()
{
#ifdef _WIN32
    return { static_cast<int>(GetLastError()), std::system_category() };
#else
    return { errno, std::system_category() };
#endif
}

std::vector<unsigned char> getRandomBytes(const size_t nbytes, const size_t reserve = 0)
{
    assert(nbytes > 0);

    std::vector<unsigned char> buf(nbytes + reserve);
    if(!randombytes(buf.data(), nbytes))
        throw std::system_error(last_error());

    return buf;
}

std::vector<unsigned char> getRandomSeed(const size_t seed_size, const std::string &entropy)
{
    auto tmp = getRandomBytes(seed_size, entropy.size());
    std::copy(begin(entropy), end(entropy), end(tmp) - entropy.size());

    return shake256(seed_size, tmp);
}

