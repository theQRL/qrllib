#include <emscripten.h>
#include <emscripten/bind.h>
#include <iostream>
#include <kyber.h>
#include <misc.h>

namespace {
    class KyberWrapper {
    explicit KyberWrapper()
        :_kyber() { }
    
    public:

        static KyberWrapper empty()
        {
            return KyberWrapper();
        }

        std::vector<uint8_t> getSKRaw()
        {   
            return _kyber.getSK() ;
        }

        std::string getSK()
        {
            return bin2hstr( _kyber.getSK() );
        }

        std::vector<uint8_t> getPKRaw()
        {   
            return _kyber.getPK() ;
        }

        std::string getPK()
        {
            return bin2hstr( _kyber.getPK() );
        }

    private:
        Kyber _kyber;
};

std::string EMSCRIPTEN_KEEPALIVE
_bin2hstr(const std::vector<unsigned char>& input)
{
    return bin2hstr(input, 0);
}

std::string EMSCRIPTEN_KEEPALIVE
_getString()
{
    return "Test String from Kyber JS Wrapper";
}

int EMSCRIPTEN_KEEPALIVE
crypto_kem_keypair(
    unsigned char pk,
    unsigned char sk)
{
    return crypto_kem_keypair(pk, sk);
}

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {

    function("getString", &_getString);
    function("crypto_kem_keypair", &crypto_kem_keypair);
    function("bin2hstr", &_bin2hstr);

    class_<KyberWrapper>("Kyber")
        .class_function("empty", &KyberWrapper::empty)
        .function("getPKRaw", &KyberWrapper::getPKRaw)
        .function("getPK", &KyberWrapper::getPK)
        .function("getSKRaw", &KyberWrapper::getSKRaw)
        .function("getSK", &KyberWrapper::getSK);
    }

}