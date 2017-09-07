// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

%include "stdint.i"
%include "carrays.i"
%include "cdata.i"
%include "std_vector.i"
%include "std_string.i"

%module pyqrlfast
%{
    #include "api.h"
    #include "xmss.h"
    #include "misc.h"
    #include "fips202.h"
    #include "hash.h"
%}

%array_class(unsigned char, ucharCArray)
%array_class(uint, uintCArray)
%array_class(uint32_t, uint32CArray)

namespace std {
  %template(intVector) vector<int>;
  %template(uintVector) vector<unsigned int>;
  %template(ucharVector) vector<unsigned char>;
  %template(doubleVector) vector<double>;
}

#%array_functions(uint32_t, uint32ArrayRaw)

%include "api.h"
%include "xmss.h"
%include "misc.h"
%include "fips202.h"
%include "hash.h"
