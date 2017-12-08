// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <algsxmss.h>
#include <crypto/xmss.h>
#include <vector>
#include <iostream>
#include "gtest/gtest.h"
#include <crypto/misc.h>
#include <crypto/xmssFast.h>

namespace {
#define XMSS_HEIGHT 8

    TEST(XMSSFAST, Instantiation) {
        std::vector<unsigned char> seed(48, 0);

        XmssFast xmss(seed, XMSS_HEIGHT);

        auto pk = xmss.getPK();
        auto sk = xmss.getSK();

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "seed:" << seed.size() << " bytes\n" << bin2hstr(seed, 48) << std::endl;
        std::cout << "pk  :" << pk.size() << " bytes\n" << bin2hstr(pk, 48) << std::endl;
        std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 48) << std::endl;

        EXPECT_EQ(seed, xmss.getSeed());
    }

    TEST(XMSSFAST, SignatureLen) {
        std::vector<unsigned char> seed(48, 0);

        XmssFast xmss4(seed, 4);
        EXPECT_EQ(2308, xmss4.getSignatureSize());

        XmssFast xmss6(seed, 6);
        EXPECT_EQ(2372, xmss6.getSignatureSize());
    }

    TEST(XMSSFAST, Sign) {
        std::vector<unsigned char> seed(48, 0);

        XmssFast xmss(seed, XMSS_HEIGHT);

        std::string message = "This is a test message";
        std::vector<unsigned char> data(message.begin(), message.end());
        EXPECT_EQ(xmss.getIndex(), 0);

        auto signature = xmss.sign(data);

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
        std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;
        EXPECT_EQ(xmss.getIndex(), 1);

        auto signature2 = xmss.sign(data);

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
        std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;

        EXPECT_NE(bin2hstr(signature), bin2hstr(signature2));
        EXPECT_EQ(xmss.getIndex(), 2);
    }


    TEST(XMSSFAST, Verify) {
        std::vector<unsigned char> seed(48, 0);

        Xmss xmss(seed, XMSS_HEIGHT);

        std::string message = "This is a test message";
        std::vector<unsigned char> data_ref(message.begin(), message.end());
        std::vector<unsigned char> data(message.begin(), message.end());

        auto pk = xmss.getPK();
        auto sk = xmss.getSK();
        std::cout << std::endl;
        std::cout << "seed:" << seed.size() << " bytes\n" << bin2hstr(seed, 32) << std::endl;
        std::cout << "pk  :" << pk.size() << " bytes\n" << bin2hstr(pk, 32) << std::endl;
        std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 32) << std::endl;

        auto signature = xmss.sign(data);

        EXPECT_EQ(data, data_ref);

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "data       :" << data.size() << " bytes\n" << bin2hstr(data, 64) << std::endl;
        std::cout << "signature  :" << signature.size() << " bytes\n" << bin2hstr(signature, 64) << std::endl;

        EXPECT_TRUE(Xmss::verify(data, signature, pk));

        signature[1] += 1;
        EXPECT_FALSE(Xmss::verify(data, signature, xmss.getPK()));
    }

    TEST(XMSSFAST, SignIndexShift) {
        std::vector<unsigned char> seed(48, 0);

        Xmss xmss1(seed, 4);
        XmssFast xmss2(seed, 4);

        std::string message = "This is a test message";
        std::vector<unsigned char> data(message.begin(), message.end());

        xmss1.setIndex(1);
        xmss2.setIndex(1);

        auto signature1 = xmss1.sign(data);
        auto signature2 = xmss2.sign(data);

        auto hstr_sig1 = bin2hstr(signature1);
        auto hstr_sig2 = bin2hstr(signature2);

        EXPECT_EQ(hstr_sig1, hstr_sig2);
//    EXPECT_EQ(signature1, signature2);
    }

}
