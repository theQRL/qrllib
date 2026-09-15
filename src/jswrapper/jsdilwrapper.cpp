#include <emscripten.h>
#include <emscripten/bind.h>
#include <cctype>
#include <iostream>
#include <stdexcept>
#include <crypto/secure_memory.h>
#include <dilithium.h>
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
            std::string sk)
        {
            qrllib::secure_memory::StringWipeGuard encoded_sk_guard(sk);
            const auto public_key = hstr2bin(pk);
            auto secret_key = decode_sensitive_hex(sk);
            qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(secret_key);
            return DilithiumWrapper(public_key, secret_key);
        }

        std::vector<uint8_t> getSKRaw()
        {   
            return _dilithium.getSK() ;
        }

        emscripten::val getSK()
        {
            auto secret_key = _dilithium.getSK();
            qrllib::secure_memory::WipeGuard<uint8_t> sk_guard(secret_key);
            auto encoded = bin2hstr(secret_key);
            qrllib::secure_memory::StringWipeGuard encoded_guard(encoded);
            return emscripten::val::u8string(encoded.c_str());
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
            auto message_bytes = decode_sensitive_hex(message);
            qrllib::secure_memory::WipeGuard<uint8_t> message_guard(message_bytes);
            auto signed_message = _dilithium.sign(message_bytes);
            qrllib::secure_memory::WipeGuard<uint8_t> signed_guard(signed_message);
            return bin2hstr(signed_message);
        }

        static std::string sign_open( std::string message_output,
                          const std::string& message_signed,
                          const std::string& pk)
        {
            qrllib::secure_memory::StringWipeGuard output_guard(message_output);
            std::vector<uint8_t> vec;
            qrllib::secure_memory::WipeGuard<uint8_t> output_bytes_guard(vec);
            auto signed_bytes = decode_sensitive_hex(message_signed);
            qrllib::secure_memory::WipeGuard<uint8_t> signed_guard(signed_bytes);
            const auto public_key = hstr2bin(pk);
            if (!Dilithium::sign_open(vec, signed_bytes, public_key)) {
                return {};
            }
            return bin2hstr(vec);
        }

        static std::string extract_message(const std::string& message_output)
        {
            auto vec = decode_sensitive_hex(message_output);
            qrllib::secure_memory::WipeGuard<uint8_t> input_guard(vec);
            auto message = Dilithium::extract_message(vec);
            qrllib::secure_memory::WipeGuard<uint8_t> message_guard(message);
            return bin2hstr(message);
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
    (void) pk;
    (void) sk;
    return -1;
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
        .function("getSKRaw", &DilithiumWrapper::getSKRaw,
                  return_value_policy::take_ownership())
        .function("getSK", &DilithiumWrapper::getSK)
        .function("sign", &DilithiumWrapper::sign);
    }

}
