// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

%{
#include <crypto/secure_memory.h>
#include <utility>
%}

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

// Go transfers each by-value result allocation into its caller-owned vector
// proxy. The WipeGuard clears the moved-from SWIG local on every exit path.
#if defined(SWIGGO)
%typemap(out) std::vector<unsigned char> {
    qrllib::secure_memory::WipeGuard<unsigned char> result_guard($1);
    *(std::vector<unsigned char> **)&$result =
        new std::vector<unsigned char>(std::move($1));
}
%typemap(out) std::vector<std::vector<unsigned char>> {
    qrllib::secure_memory::WipeGuard<std::vector<unsigned char>> result_guard($1);
    *(std::vector<std::vector<unsigned char>> **)&$result =
        new std::vector<std::vector<unsigned char>>(std::move($1));
}
#endif

%array_class(unsigned char, ucharCArray)
%array_class(unsigned int, uintCArray)
%array_class(uint32_t, uint32CArray)

namespace std {
#if defined(SWIGGO)
  %extend vector<unsigned char> {
    ~vector() {
      if ($self != nullptr) {
        qrllib::secure_memory::wipe(*$self);
      }
      delete $self;
    }
  }
#endif
  %template(intVector) vector<int>;
  %template(uintVector) vector<unsigned int>;
  %template(ucharVector) vector<unsigned char>;
  %template(charVector) vector<char>;
  %template(doubleVector) vector<double>;
  %template(_string_list) vector<string>;
#if defined(SWIGGO)
  %extend vector<vector<unsigned char>> {
    ~vector() {
      if ($self != nullptr) {
        qrllib::secure_memory::wipe(*$self);
      }
      delete $self;
    }
  }
#endif
  %template(_string_list_list) vector<vector<unsigned char>>;
}

// Python converts each SWIG result in place and wipes it immediately after
// creating the Python value. These typemaps follow the vector templates so
// they take precedence over std_vector.i's generated conversion typemaps.
#if defined(SWIGPYTHON)
%typemap(out) std::vector<unsigned char> {
    qrllib::secure_memory::WipeGuard<unsigned char> result_guard($1);
    $result = swig::from($1);
}
%typemap(out) std::vector<std::vector<unsigned char>> {
    qrllib::secure_memory::WipeGuard<std::vector<unsigned char>> result_guard($1);
    $result = swig::from($1);
}
#endif

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
