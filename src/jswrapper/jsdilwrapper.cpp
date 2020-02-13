#include <emscripten.h>
#include <emscripten/bind.h>
#include <iostream>
#include <dilithium.h>
#include <misc.h>

namespace {
    class DilithiumWrapper {
    explicit DilithiumWrapper()
        :_dilithium() { }

    explicit DilithiumWrapper(
        const std::vector<uint8_t>& pk,
        const std::vector<uint8_t>& sk)
        :_dilithium(pk, sk) { }
    
    public:

        static DilithiumWrapper empty()
        {
            return DilithiumWrapper();
        }

        static DilithiumWrapper fromKeys(
            const std::string& pk,
            const std::string& sk)
        {
            return DilithiumWrapper( hstr2bin(pk), hstr2bin(sk) );
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

        std::string sign(const std::string& message)
        {
            return bin2hstr( _dilithium.sign( hstr2bin(message) ) );
        }

        static std::string sign_open( std::string message_output,
                          const std::string& message_signed,
                          const std::string& pk)
        { 
            std::vector<uint8_t> vec;
            vec.assign(message_output.begin(), message_output.end());
            Dilithium::sign_open( vec, hstr2bin(message_signed), hstr2bin(pk));
            return bin2hstr(vec);
        }

        static std::string extract_message(const std::string& message_output)
        {
            std::vector<uint8_t> vec;
            vec.assign( hstr2bin(message_output).begin(), hstr2bin(message_output).end());
            return bin2hstr( Dilithium::extract_message( vec ) );
        }

    private:
        Dilithium _dilithium;
};

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
        .class_function("fromKeys", &DilithiumWrapper::fromKeys)
        .class_function("sign_open", &DilithiumWrapper::sign_open)
        .class_function("extract_message", &DilithiumWrapper::extract_message)
        .function("getPKRaw", &DilithiumWrapper::getPKRaw)
        .function("getPK", &DilithiumWrapper::getPK)
        .function("getSKRaw", &DilithiumWrapper::getSKRaw)
        .function("getSK", &DilithiumWrapper::getSK)
        .function("sign", &DilithiumWrapper::sign);
    }

}