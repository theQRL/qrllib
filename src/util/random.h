#pragma once

#include <cstdint>
#include <vector>

std::vector<unsigned char> getRandomBytes(const size_t nbytes, const size_t reserve = 0);
std::vector<unsigned char> getRandomSeed(const size_t seed_size, const std::string &entropy);

