// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include <xmss-alt/algsxmss.h>
#include <xmssBasic.h>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>
#include <qrl/qrlHelper.h>

namespace {
#define XMSS_HEIGHT 4

    TEST(XmssBasic_Default, Instantiation) {
        std::vector<unsigned char> seed(48, 0);

        XmssBasic xmss(seed, XMSS_HEIGHT);

        auto pk = xmss.getPK();
        auto sk = xmss.getSK();

        std::cout << std::endl;
        std::cout << std::endl;
        std::cout << "seed:" << seed.size() << " bytes\n" << bin2hstr(seed, 16) << std::endl;
        std::cout << "pk  :" << pk.size() << " bytes\n" << bin2hstr(pk, 16) << std::endl;
        std::cout << "sk  :" << sk.size() << " bytes\n" << bin2hstr(sk, 16) << std::endl;
        std::cout << "descr:" << bin2hstr(xmss.getDescriptor().getBytes()) << std::endl;
        std::cout << "addr :" << bin2hstr(xmss.getAddress()) << std::endl;

        EXPECT_EQ(seed, xmss.getSeed());
        EXPECT_EQ("000000000000000000000000000000000000000000000000"
                  "000000000000000000000000000000000000000000000000",
                  bin2hstr(xmss.getSeed()));

        EXPECT_TRUE(xmss.getDescriptor().getHashFunction() == eHashFunction::SHAKE_128);

        EXPECT_EQ("0102", bin2hstr(xmss.getDescriptor().getBytes()));
        EXPECT_EQ("01020000000000000000000000000000000000000000000000"
                  "00000000000000000000000000000000000000000000000000",
                  bin2hstr(xmss.getExtendedSeed()));
        EXPECT_EQ("010274764b521b002b55c57fa182142310c0bd6f2be9b3d673bf2e7f731e86da45edac082a29",
                  bin2hstr(xmss.getAddress()));

        EXPECT_EQ("010274764b521b002b55c57fa182142310c0bd6f2be9b3d673bf2e7f731e86da45edac082a29",
                  bin2hstr(QRLHelper::getAddress( xmss.getPK())));

    }

    TEST(XmssBasic_Default, SignatureLen) {
        std::vector<unsigned char> seed(48, 0);

        XmssBasic xmss4(seed, 4);
        EXPECT_EQ(2308, xmss4.getSignatureSize());

        XmssBasic xmss6(seed, 6);
        EXPECT_EQ(2372, xmss6.getSignatureSize());
    }

    TEST(XmssBasic_Default, Sign) {
        std::vector<unsigned char> seed(48, 0);

        XmssBasic xmss(seed, XMSS_HEIGHT);

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


    TEST(XmssBasic_Default, Verify) {
        std::vector<unsigned char> seed;
        for(unsigned char i=0; i<48; i++)
            seed.push_back(i);

        XmssBasic xmss(seed, XMSS_HEIGHT);

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

        EXPECT_TRUE(XmssBasic::verify(data, signature, pk));

        signature[1] += 1;
        EXPECT_FALSE(XmssBasic::verify(data, signature, xmss.getPK()));
    }
}
