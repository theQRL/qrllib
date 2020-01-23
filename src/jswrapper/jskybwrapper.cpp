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

        bool kem_encode(const std::string& input)
        {
            return _kyber.kem_encode( hstr2bin(input) );
        }

        bool kem_decode(const std::string& input)
        {
            return _kyber.kem_decode( hstr2bin(input) );
        }

        std::string getCypherText()
        {
            return bin2hstr( _kyber.getCypherText() );
        }

        std::string getMyKey()
        {
            return bin2hstr( _kyber.getMyKey() );
        }

    private:
        Kyber _kyber;
};

// bool EMSCRIPTEN_KEEPALIVE
// kem_encode(const std::vector<uint8_t> &other_pk)
// {
//     return kem_encode(other_pk);
// }

std::string EMSCRIPTEN_KEEPALIVE
_bin2hstr(const std::vector<unsigned char>& input)
{
    return bin2hstr(input, 0);
}

std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE
_hstr2bin(const std::string& input)
{
    return hstr2bin(input);
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
        .function("kem_encode", &KyberWrapper::kem_encode)
        .function("kem_decode", &KyberWrapper::kem_decode)
        .function("getPKRaw", &KyberWrapper::getPKRaw)
        .function("getPK", &KyberWrapper::getPK)
        .function("getSKRaw", &KyberWrapper::getSKRaw)
        .function("getSK", &KyberWrapper::getSK)
        .function("getCypherText", &KyberWrapper::getCypherText)
        .function("getMyKey", &KyberWrapper::getMyKey);
    }

}