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

%module dilithium
%{
#include "dilithium/dilithium.h"
%}

%include "dilithium/dilithium.h"
