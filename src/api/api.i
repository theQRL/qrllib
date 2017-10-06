// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

%include "stdint.i"
%include "carrays.i"
%include "cdata.i"
%include "std_vector.i"
%include "std_string.i"
%include "stl.i"
%include "std_except.i"
%include "std_shared_ptr.i"

%array_class(unsigned char, ucharCArray)
%array_class(uint, uintCArray)
%array_class(uint32_t, uint32CArray)

namespace std {
  %template(intVector) vector<int>;
  %template(uintVector) vector<unsigned int>;
  %template(ucharVector) vector<unsigned char>;
  %template(charVector) vector<char>;
  %template(doubleVector) vector<double>;
  %template(_string_list) vector<string>;
  %template(_string_list_list) vector<vector<unsigned char>>;
}

%shared_ptr(XmssBase)
%shared_ptr(Xmss)
%shared_ptr(XmssFast)

// %array_functions(uint32_t, uint32ArrayRaw)

%module pyqrllib
%{
    #include "api.h"
    #include "xmss.h"
    #include "misc.h"
    #include "hashing.h"
    #include "xmssBase.h"
    #include "xmssFast.h"
    #include "xmssPool.h"
%}

%include "api.h"
%include "misc.h"
%include "hashing.h"
%include "xmss.h"
%include "xmssBase.h"
%include "xmssFast.h"
%include "xmssPool.h"
