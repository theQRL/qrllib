// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#ifndef QRLFAST_XMSS_H
#define QRLFAST_XMSS_H

#include<vector>

// This is unfortunately not fully supported by SWIG
// using TSIGNATURE = std::vector<unsigned char>;
// using TMESSAGE = std::vector<unsigned char>;

#define TSIGNATURE std::vector<unsigned char>
#define TMESSAGE std::vector<unsigned char>
#define TSEED std::vector<unsigned char>
#define TKEY std::vector<unsigned char>

class Xmss {
public:
    // TODO: Apply consts, this requires changes in the underlying lib
    Xmss(const TSEED &seed, unsigned char height);

    inline int getHeight()
    {
        return _height;
    }

    TSIGNATURE sign(const TMESSAGE &message);

    bool verify(const TMESSAGE &message, TSIGNATURE &signature);

private:
    int _height;
};

#endif //QRLFAST_XMSS_H
