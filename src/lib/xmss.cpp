#include <iostream>
#include "xmss.h"
#include "algsxmss.h"

Xmss::Xmss(const TSEED &seed, unsigned char height): _height(height)
{
    std::cout << "\nCreating Xmss" << std::endl;

    TKEY pk(1000);
    TKEY sk(1000);
    auto seed_ptr = const_cast<unsigned char *>(seed.data());

    xmss_Genkeypair(pk.data(), sk.data(), seed_ptr, height);

    std::cout << "Done" << std::endl;
}

TSIGNATURE Xmss::sign(const TMESSAGE &message)
{
    std::cout << "Call to sign" << std::endl;

    for(auto v : message)
    {
        std::cout << v << std::endl;
    }

    auto answer = std::vector<unsigned char>(message);
    answer.push_back(80);

    return answer;
}

bool Xmss::verify(const TMESSAGE &message,
                  TSIGNATURE &signature)
{
    std::cout << "Call to verify" << std::endl;
    return false;
}
