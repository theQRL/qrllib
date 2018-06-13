#include <emscripten.h>
#include <emscripten/bind.h>
#include <iostream>
#include <xmssFast.h>
#include <hashing.h>
#include <misc.h>
#include <wordlist.h>
#include <qrlHelper.h>
#include <qrlDescriptor.h>

namespace {

class XmssWrapper {
    explicit XmssWrapper(
            const std::vector<uint8_t>& seed,
            uint8_t height,
            eHashFunction hashFunction)
            :_xmss(seed, height, hashFunction) { }
public:
    unsigned int getIndex()
    {
        return _xmss.getIndex();
    }

    int getHeight()
    {
        return _xmss.getHeight();
    }

    TKEY getPKRaw()
    {
        return _xmss.getPK();
    }

    std::string getPK()
    {
        return bin2hstr( _xmss.getPK() );
    }

    std::vector<uint8_t> getAddressRaw()
    {
        return _xmss.getAddress();
    }

    std::string getAddress()
    {
        return 'Q' + bin2hstr(_xmss.getAddress());
    }

    std::string getHexSeed()
    {
        auto extended_seed = _xmss.getExtendedSeed();
        return bin2hstr(extended_seed);
    }

    std::string getMnemonic()
    {
        auto extended_seed = _xmss.getExtendedSeed();
        return bin2mnemonic(extended_seed);
    }

    /////////////////////////////////////
    /////////////////////////////////////

    static XmssWrapper fromParameters(
            const std::vector<uint8_t>& random_bytes,
            uint8_t height,
            eHashFunction hash_function)
    {
        return XmssWrapper(random_bytes, height, hash_function);
    }

    static XmssWrapper fromHexSeed(const std::string hexseed)
    {
        auto extended_seed = hstr2bin(hexseed);
        auto descr = QRLDescriptor::fromExtendedSeed(extended_seed);

        auto raw_seed = std::vector<uint8_t>(
            extended_seed.cbegin()+QRLDescriptor::getSize(),
            extended_seed.cend()
        );

        return XmssWrapper(
            raw_seed,
            descr.getHeight(),
            descr.getHashFunction()
        );
    }

    static XmssWrapper fromMnemonic(const std::string mnemonic)
    {
        auto extended_seed = mnemonic2bin(mnemonic);
        auto descr = QRLDescriptor::fromExtendedSeed(extended_seed);

        auto raw_seed = std::vector<uint8_t>(
            extended_seed.cbegin()+QRLDescriptor::getSize(),
            extended_seed.cend()
        );

        return XmssWrapper(
            raw_seed,
            descr.getHeight(),
            descr.getHashFunction()
        );
    }

    /////////////////////////////////////
    /////////////////////////////////////

    unsigned int setIndex(unsigned int new_index)
    {
        return _xmss.setIndex(new_index);
    }

    TSIGNATURE sign(const TMESSAGE& message)
    {
        return _xmss.sign(message);
    }

    static bool verify(
            const TMESSAGE& message,
            const TSIGNATURE& signature,
            const TKEY& pk)
    {
        return XmssFast::verify(message, signature, pk);
    }

private:
    XmssFast _xmss;
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

std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE
_str2bin(const std::string& str)
{
    return str2bin(str);
}

std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE
_mnemonic2bin(const std::string& mnemonic)
{
    return mnemonic2bin(mnemonic);
}

std::string EMSCRIPTEN_KEEPALIVE
_bin2mnemonic(const std::vector<unsigned char>& vec)
{
    return bin2mnemonic(vec);
}

std::vector<uint8_t> getBinAddress(std::string address_str)
{
    if (address_str.size()<1+2*QRLDescriptor::getSize())
    {
        throw std::invalid_argument("Invalid address");
    }

    return hstr2bin(address_str.substr(1));
}

eHashFunction EMSCRIPTEN_KEEPALIVE
_getHashFunction(std::string address_str)
{
    auto address = getBinAddress(address_str);

    if (address.size() < QRLDescriptor::getSize())
    {
        throw std::invalid_argument("Invalid address");
    }

    auto descr = QRLDescriptor::fromBytes(
            std::vector<uint8_t>(
                    address.cbegin(),
                    address.cbegin()+QRLDescriptor::getSize()));

    return descr.getHashFunction();
}

eSignatureType EMSCRIPTEN_KEEPALIVE
_getSignatureType(std::string address_str)
{
    auto address = getBinAddress(address_str);

    if (address.size()<QRLDescriptor::getSize()) {
        throw std::invalid_argument("Invalid address");
    }

    auto descr = QRLDescriptor::fromBytes(
            std::vector<uint8_t>(
                    address.cbegin(),
                    address.cbegin()+QRLDescriptor::getSize()));

    return descr.getSignatureType();
}

uint8_t EMSCRIPTEN_KEEPALIVE
_getHeight(std::string address_str)
{
    auto address = getBinAddress(address_str);

    auto descr = QRLDescriptor::fromBytes(
            std::vector<uint8_t>(
                    address.cbegin(),
                    address.cbegin()+QRLDescriptor::getSize()));

    return descr.getHeight();
}

std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE
_getAddressRaw(const std::vector<unsigned char>& epk)
{
    return QRLHelper::getAddress(epk);
}

std::string EMSCRIPTEN_KEEPALIVE
_getAddress(std::string epk_str)
{
    if (epk_str.size()!=2*67)
    {
        throw std::invalid_argument("Invalid epk");
    }

    auto epk = hstr2bin(epk_str);
    return _bin2hstr(_getAddressRaw(epk));
}

bool EMSCRIPTEN_KEEPALIVE
_validateAddressRaw(const std::vector<unsigned char>& address)
{
    return QRLHelper::addressIsValid(address);
}

bool EMSCRIPTEN_KEEPALIVE
_validateAddress(std::string address_str)
{
    auto address = getBinAddress(address_str);
    return _validateAddressRaw(address);
}

std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE
_sha2_256(const std::vector<unsigned char>& data)
{
    return sha2_256(data);
}

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_module) {
        register_vector<uint8_t>("Uint8Vector");

        // HASH FUNCTIONS
        function("sha2_256", &_sha2_256);

        // UTILITIES
        function("bin2hstr", &_bin2hstr);
        function("hstr2bin", &_hstr2bin);
        function("str2bin", &_str2bin);
        function("mnemonic2bin", &_mnemonic2bin);
        function("bin2mnemonic", &_bin2mnemonic);
        function("getAddress", &_getAddress);
        function("getAddressRaw", &_getAddressRaw);
        function("validateAddress", &_validateAddress);
        function("validateAddressRaw", &_validateAddressRaw);

        // DESCRIPTOR
        function("getHashFunction", &_getHashFunction);
        function("getSignatureType", &_getSignatureType);
        function("getHeight", &_getHeight);

        enum_<eHashFunction>("eHashFunction")
            .value("SHA2_256", eHashFunction::SHA2_256)
            .value("SHAKE_128", eHashFunction::SHAKE_128)
            .value("SHAKE_256", eHashFunction::SHAKE_256)
            ;

        enum_<eSignatureType>("eSignatureType")
            .value("XMSS", eSignatureType::XMSS)
        ;

        // XMSS
        class_<XmssWrapper>("Xmss")
        .class_function("fromParameters", &XmssWrapper::fromParameters)
        .class_function("fromHexSeed", &XmssWrapper::fromHexSeed)
        .class_function("fromMnemonic", &XmssWrapper::fromMnemonic)

        .function("getIndex", &XmssWrapper::getIndex)
        .function("getHeight", &XmssWrapper::getHeight)

        .function("getPKRaw", &XmssWrapper::getPKRaw)
        .function("getPK", &XmssWrapper::getPK)

        .function("getAddressRaw", &XmssWrapper::getAddressRaw)
        .function("getAddress", &XmssWrapper::getAddress)

        .function("getHexSeed", &XmssWrapper::getHexSeed)
        .function("getMnemonic", &XmssWrapper::getMnemonic)

        .function("setIndex", &XmssWrapper::setIndex)
        .function("sign", &XmssWrapper::sign)
        .class_function("verify", &XmssWrapper::verify);
}
}