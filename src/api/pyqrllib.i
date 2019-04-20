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
%include "exception.i"

#if defined(SWIGPYTHON)
%{
SWIGEXPORT void HandleAllExceptions()
{
    try
    {
        throw;
    }
    catch(const std::invalid_argument& e)
    {
        SWIG_Error(SWIG_ValueError, e.what());
    }
    catch(const std::exception& e)
    {
        SWIG_Error(SWIG_RuntimeError, e.what());
    }
    catch (...)
    {
        SWIG_Error(SWIG_UnknownError, "unknown error");
    }
}
%}

%exception {
    try {   $action }
    catch (...) {
        HandleAllExceptions();
        SWIG_fail;
    }
}
#else
%exception {
    try {   $action }
    catch (std::exception &e) {
        _swig_gopanic(e.what());
    }
}

#endif

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

#if defined(SWIGPYTHON)
%shared_ptr(XmssBase)
%shared_ptr(XmssBasic)
%shared_ptr(XmssFast)
#endif

// %array_functions(uint32_t, uint32ArrayRaw)

#if defined(SWIGPYTHON)
%module pyqrllib
#else
%module goqrllib
#endif
%{
    #include "qrl/misc.h"
    #include "qrl/hashing.h"
    #include "qrl/qrlHelper.h"
    #include "qrl/xmssBasic.h"
    #include "qrl/xmssBase.h"
    #include "qrl/xmssFast.h"
    #include "qrl/xmssPool.h"
%}

%include "qrl/misc.h"
%include "qrl/hashing.h"
%include "qrl/qrlHelper.h"
%include "qrl/xmssBasic.h"
%include "qrl/xmssBase.h"
%include "qrl/xmssFast.h"
%include "qrl/xmssPool.h"
