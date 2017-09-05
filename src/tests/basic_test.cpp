#include <algsxmss.h>
#include <xmss.h>
#include <vector>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>

// Direct access to XMSS-Reference
#include "randombytes.h"

namespace {
    TEST(XMSS_Reference, Correct_Linking) {
        unsigned char tmp[100];

        randombytes(tmp, 100);

        EXPECT_EQ(1, 1);
    }

//    TEST(XMSS_Alt, GenKeyPairs) {
//        unsigned char pk[1000];
//        unsigned char sk[1000];
//        unsigned char seed[1000];
//
//        xmss_Genkeypair(pk, sk, seed, 10);
//
//        EXPECT_EQ(1, 1);
//    }

#define XMSS_HEIGHT 4

    TEST(XMSS, vec2hex) {
        std::vector<unsigned char> data;

        std::cout << std::endl;

        data.push_back(1);
        data.push_back(2);
        std::cout << "data:\n" << vec2hexstr(data, 4) << std::endl;

        auto data_long = std::vector<unsigned char>({0, 1, 2, 3, 4, 6, 7, 8});
        std::cout << "data_long:\n" << vec2hexstr(data_long, 4) << std::endl;
    }

    TEST(XMSS, Instantiation) {
        std::vector<unsigned char> seed(32, 0);

        Xmss xmss(seed, XMSS_HEIGHT);

        auto pk = xmss.getPK();
        auto sk = xmss.getSK();

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "seed:" << seed.size() << " bytes\n" << vec2hexstr(seed, 32) << std::endl;
        std::cout << "pk  :" << pk.size() << " bytes\n" << vec2hexstr(pk, 32) << std::endl;
        std::cout << "sk  :" << sk.size() << " bytes\n" << vec2hexstr(sk, 32) << std::endl;

        EXPECT_EQ(seed, xmss.getSeed());
    }

    TEST(XMSS, SignatureLen) {
        std::vector<unsigned char> seed(32, 0);

        Xmss xmss4(seed, 4);
        EXPECT_EQ(2308, xmss4.getSignatureSize());

        Xmss xmss6(seed, 6);
        EXPECT_EQ(2372, xmss6.getSignatureSize());
    }

    TEST(XMSS, Sign) {
        std::vector<unsigned char> seed(32, 0);

        Xmss xmss(seed, XMSS_HEIGHT);

        std::string message = "This is a test message";
        std::vector<unsigned char> data(message.begin(), message.end());

        auto signature = xmss.sign(data);

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "data       :" << data.size() << " bytes\n" << vec2hexstr(data, 64) << std::endl;
        std::cout << "signature  :" << signature.size() << " bytes\n" << vec2hexstr(signature, 64) << std::endl;
    }


    TEST(XMSS, Verify) {
        std::vector<unsigned char> seed(32, 0);

        Xmss xmss(seed, XMSS_HEIGHT);

        std::string message = "This is a test message";
        std::vector<unsigned char> data_ref(message.begin(), message.end());
        std::vector<unsigned char> data(message.begin(), message.end());

        auto pk = xmss.getPK();
        auto sk = xmss.getSK();
        std::cout << std::endl;
        std::cout << "seed:" << seed.size() << " bytes\n" << vec2hexstr(seed, 32) << std::endl;
        std::cout << "pk  :" << pk.size() << " bytes\n" << vec2hexstr(pk, 32) << std::endl;
        std::cout << "sk  :" << sk.size() << " bytes\n" << vec2hexstr(sk, 32) << std::endl;

        auto signature = xmss.sign(data);

        EXPECT_EQ(data, data_ref);

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "data       :" << data.size() << " bytes\n" << vec2hexstr(data, 64) << std::endl;
        std::cout << "signature  :" << signature.size() << " bytes\n" << vec2hexstr(signature, 64) << std::endl;

        EXPECT_TRUE(xmss.verify(data, signature, xmss.getPK(), XMSS_HEIGHT));

//        signature[1] += 1;
//        EXPECT_FALSE(xmss.verify(data, signature, xmss.getPK(), XMSS_HEIGHT));
    }
}
