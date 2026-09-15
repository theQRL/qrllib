#include <emscripten.h>
#include <emscripten/bind.h>
#include <cctype>
#include <iostream>
#include <stdexcept>
#include <crypto/secure_memory.h>
#include <kyber.h>
#include <misc.h>

namespace {

    std::vector<uint8_t> decode_sensitive_hex(const std::string& input)
    {
        if (input.size() % 2 != 0) {
            throw std::invalid_argument(
                "hex string is expected to have an even number of characters");
        }

        std::vector<uint8_t> result;
        qrllib::secure_memory::WipeGuard<uint8_t> result_guard(result);
        result.reserve(input.size() / 2);
        for (std::size_t i = 0; i < input.size(); i += 2) {
            const auto first = static_cast<unsigned char>(input[i]);
            const auto second = static_cast<unsigned char>(input[i + 1]);
            if (!std::isxdigit(first) || !std::isxdigit(second)) {
                throw std::invalid_argument("invalid hex digits in the string");
            }

            const auto high = std::tolower(first);
            const auto low = std::tolower(second);
            const auto high_value = std::isdigit(high) ? high - '0' : high - 'a' + 10;
            const auto low_value = std::isdigit(low) ? low - '0' : low - 'a' + 10;
            result.push_back(static_cast<uint8_t>((high_value << 4) + low_value));
        }
        result_guard.release();
        return result;
    }

    class KyberWrapper {
        
    explicit KyberWrapper(
        const std::vector<uint8_t>& pk,
        const std::vector<uint8_t>& sk)
        :_kyber(pk, sk) { }

    explicit KyberWrapper()
        :_kyber() { }
    
    public:

        std::vector<uint8_t> getSKRaw()
        {   
            return _kyber.getSK() ;
        }

        emscripten::val getSK()
        {
            auto secret_key = _kyber.getSK();
            qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(secret_key);
            auto encoded = bin2hstr(secret_key);
            qrllib::secure_memory::StringWipeGuard encoded_guard(encoded);
            return emscripten::val::u8string(encoded.c_str());
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
            // Parsing can throw before the native size boundary is reached.
            // Clear the prior operation result first so that path cannot leave
            // an old shared key or ciphertext observable.
            _kyber.kem_encode({});
            const auto peer_pk = hstr2bin(input);
            return _kyber.kem_encode(peer_pk);
        }

        bool kem_decode(const std::string& input)
        {
            _kyber.kem_decode({});
            const auto ciphertext = hstr2bin(input);
            return _kyber.kem_decode(ciphertext);
        }

        std::string getCypherText()
        {
            return bin2hstr( _kyber.getCypherText() );
        }

        emscripten::val getMyKey()
        {
            auto shared_key = _kyber.getMyKey();
            qrllib::secure_memory::WipeGuard<uint8_t> key_guard(shared_key);
            auto encoded = bin2hstr(shared_key);
            qrllib::secure_memory::StringWipeGuard encoded_guard(encoded);
            return emscripten::val::u8string(encoded.c_str());
        }

        /////////////////////////////////////
        /////////////////////////////////////

        static KyberWrapper empty()
        {
            return KyberWrapper();
        }

        static KyberWrapper fromKeys(
            const std::string& pk,
            std::string sk)
        {
            qrllib::secure_memory::StringWipeGuard encoded_sk_guard(sk);
            const auto public_key = hstr2bin(pk);
            auto secret_key = decode_sensitive_hex(sk);
            qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(secret_key);
            return KyberWrapper(public_key, secret_key);
        }

    private:
        Kyber _kyber;
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
    return "Test String from Kyber JS Wrapper";
}

int EMSCRIPTEN_KEEPALIVE
crypto_kem_keypair(
    unsigned char pk,
    unsigned char sk)
{
    (void) pk;
    (void) sk;
    return -1;
}

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {

    function("getString", &_getString);
    function("crypto_kem_keypair", &crypto_kem_keypair);
    function("bin2hstr", &_bin2hstr);

    class_<KyberWrapper>("Kyber")
        .class_function("fromKeys", &KyberWrapper::fromKeys)
        .class_function("empty", &KyberWrapper::empty)
        .function("kem_encode", &KyberWrapper::kem_encode)
        .function("kem_decode", &KyberWrapper::kem_decode)
        .function("getPKRaw", &KyberWrapper::getPKRaw)
        .function("getPK", &KyberWrapper::getPK)
        .function("getSKRaw", &KyberWrapper::getSKRaw,
                  return_value_policy::take_ownership())
        .function("getSK", &KyberWrapper::getSK)
        .function("getCypherText", &KyberWrapper::getCypherText)
        .function("getMyKey", &KyberWrapper::getMyKey);
    }

}
