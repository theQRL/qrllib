// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#ifndef QRLLIB_KYBER_H
#define QRLLIB_KYBER_H

#define KYBER_K 3

#include <string>
#include <vector>
#include <kyber/ref/api.h>
#include <kyber/ref/randombytes.h>


class Kyber {
public:
    Kyber();

    Kyber(const std::vector<uint8_t> &pk,
          const std::vector<uint8_t> &sk);

    virtual ~Kyber() = default;

    std::vector<uint8_t> getPK() { return _pk; }

    std::vector<uint8_t> getSK() { return _sk; }

    std::vector<uint8_t> getMyKey() { return _key; }

    std::vector<uint8_t> getCypherText() { return _ct; }

    bool kem_encode(const std::vector<uint8_t> &other_pk);

    bool kem_decode(const std::vector<uint8_t> &cyphertext);

protected:
    std::vector<uint8_t> _pk;
    std::vector<uint8_t> _sk;
    std::vector<uint8_t> _key;
    std::vector<uint8_t> _ct;
};

#endif //QRLLIB_DILITHIUM_H
