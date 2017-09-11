// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#include "misc.h"
#include <sstream>
#include <iomanip>

std::string vec2hexstr(const std::vector<unsigned char> &vec, int wrap)
{
    std::stringstream ss;

    int count = 0;
    for(auto val : vec)
    {
        if (wrap>0)
        {
            count++;
            if (count>wrap)
            {
                ss << "\n";
                count = 1;
            }
        }
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)val;
    }

    return ss.str();
}

std::string vec2hexstr(const std::vector<char> &vec, int wrap)
{
    std::stringstream ss;

    int count = 0;
    for(auto val : vec)
    {
        if (wrap>0)
        {
            count++;
            if (count>wrap)
            {
                ss << "\n";
                count = 1;
            }
        }
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)val;
    }

    return ss.str();
}
