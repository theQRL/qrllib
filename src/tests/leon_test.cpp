#include <algsxmss.h>
#include <xmss.h>
#include <vector>
#include <iostream>
#include "gtest/gtest.h"
#include <misc.h>
#include <algsxmss_fast.h>

// Direct access to XMSS-Reference
#include "randombytes.h"

namespace {
    TEST(XMSS_Fast, LeonsTest) {
        unsigned char pk[64];
        unsigned char sk[4+4*32];
        bds_state s;
        unsigned char seed[32];
        unsigned char h = 8;
            unsigned int k = 2;
        unsigned int n = 32;
        printf("before keygen");

            unsigned char stack[(h+1)*n];
            unsigned int stackoffset = 0;
            unsigned char stacklevels[h+1];
            unsigned char auth[(h)*n];
            unsigned char keep[(h >> 1)*n];
            treehash_inst treehash[h-k];
            unsigned char th_nodes[(h-k)*n];
            unsigned char retain[((1 << k) - k - 1)*n];
            bds_state *state = &s;
            for (int i = 0; i < h-k; i++)
                    treehash[i].node = &th_nodes[n*i];
            xmss_set_bds_state(state, stack, stackoffset, stacklevels, auth, keep, treehash, retain, 0);

        xmssfast_Genkeypair(pk, sk, state,seed, h);

        for (int i = 0; i < n; i++) {
            printf("%d", pk[i]);
            //if (pk[n+i] != sk[4+2*n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
            //if (pk[i] != sk[4+3*n+i]) printf("pk.root != sk.root %llu",i);
        }

        unsigned char msg[32] = {0};
        unsigned long long siglen = 4 + 32 + 67 * 32 + h * 32 + 32;
        unsigned char sign[10000] = {0};
        siglen = 0;
        int x;
        x = xmssfast_Signmsg(sk, state, sign, msg,32, h);
        for(int i = 0 ; i < 10; i++){
            printf("%d",sign[i]);
        }
        printf("\n %llu \n",siglen);
        printf("\n%d\n",x);

        for (int i = 0; i < n; i++) {
            printf("%d", sign[i]);
            //if (pk[n+i] != sk[4+2*n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
            //if (pk[i] != sk[4+3*n+i]) printf("pk.root != sk.root %llu",i);
        }
        unsigned long long m = 32;
        x = xmssfast_Verifysig(msg,32, sign,pk, h);
        printf("\n%d\n",x);
    }
}
