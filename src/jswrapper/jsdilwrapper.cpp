#include <emscripten.h>
#include <emscripten/bind.h>
#include <iostream>
#include <dilithium.h>
#include <misc.h>

namespace {
    class DilithiumWrapper {
    explicit DilithiumWrapper()
        :_dilithium() { }
    
    public:

        static DilithiumWrapper empty()
        {
            return DilithiumWrapper();
        }

        std::vector<uint8_t> getSKRaw()
        {   
            return _dilithium.getSK() ;
        }

        std::string getSK()
        {
            return bin2hstr( _dilithium.getSK() );
        }

        std::vector<uint8_t> getPKRaw()
        {   
            return _dilithium.getPK() ;
        }

        std::string getPK()
        {
            return bin2hstr( _dilithium.getPK() );
        }

    private:
        Dilithium _dilithium;
};

std::string EMSCRIPTEN_KEEPALIVE
_bin2hstr(const std::vector<unsigned char>& input)
{
    return bin2hstr(input, 0);
}

std::string EMSCRIPTEN_KEEPALIVE
_getString()
{
    return "Test String from Dilithium JS Wrapper";
}

int EMSCRIPTEN_KEEPALIVE
crypto_sign_keypair(
    unsigned char pk,
    unsigned char sk)
{
    return crypto_sign_keypair(pk, sk);
}

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {

    function("getString", &_getString);
    function("crypto_sign_keypair", &crypto_sign_keypair);
    function("bin2hstr", &_bin2hstr);

    class_<DilithiumWrapper>("Dilithium")
        .class_function("empty", &DilithiumWrapper::empty)
        .function("getPKRaw", &DilithiumWrapper::getPKRaw)
        .function("getPK", &DilithiumWrapper::getPK)
        .function("getSKRaw", &DilithiumWrapper::getSKRaw)
        .function("getSK", &DilithiumWrapper::getSK);
    }

}