// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLLIB_XMSS_FAST_H
#define QRLLIB_XMSS_FAST_H

#include "xmssBase.h"
#include <stdexcept>
#include <xmss-alt/algsxmss_fast.h>

class XmssFast : public XmssBase {
public:
    // TODO: Fix constness / passing by copy, this requires changes in the underlying lib
    XmssFast(const TSEED &seed,
             unsigned char height,
             eHashFunction hashFunction = eHashFunction::SHAKE_128,
             eAddrFormatType addrFormatType = eAddrFormatType::SHA256_2X ) throw(std::invalid_argument);

    TSIGNATURE sign(const TMESSAGE &message) override;

    unsigned int setIndex(unsigned int new_index) throw(std::invalid_argument);

protected:
    // FIXME: This needs refactoring (encapsulate)

    bds_state _state;
    unsigned int _stackoffset = 0;
    std::vector<unsigned char> _stack;
    std::vector<unsigned char> _stacklevels;
    std::vector<unsigned char> _auth;

    std::vector<unsigned char> _keep;
    std::vector<treehash_inst> _treehash;
    std::vector<unsigned char> _th_nodes;
    std::vector<unsigned char> _retain;
};

#endif //QRLLIB_XMSS_FAST_H
