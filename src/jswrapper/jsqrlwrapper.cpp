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

    class XmssWrapper
    {
    public:
        explicit XmssWrapper(const std::vector<unsigned char> &seed, unsigned char height) : _xmss(seed, height) {}

        TSIGNATURE sign(const TMESSAGE &message)    {   return _xmss.sign(message);     }

        TKEY getSK() {  return _xmss.getSK(); }
        TKEY getPK() {  return _xmss.getPK(); }
        TSEED getSeed() {  return _xmss.getSeed(); }
        TSEED getExtendedSeed() {  return _xmss.getExtendedSeed(); }
        int getHeight() {  return _xmss.getHeight(); }

        TKEY getRoot() {  return _xmss.getRoot(); }
        TKEY getPKSeed() {  return _xmss.getPKSeed(); }
        TKEY getSKSeed() {  return _xmss.getSKSeed(); }
        TKEY getSKPRF() {  return _xmss.getSKPRF(); }

        std::vector<uint8_t> getAddress() {  return _xmss.getAddress(); }

        unsigned int getIndex() {  return _xmss.getIndex(); }
        unsigned int setIndex(unsigned int new_index) {  return _xmss.setIndex(new_index); }

        static bool verify(const TMESSAGE &message,
                           const TSIGNATURE &signature,
                           const TKEY &pk)
        {
            return XmssFast::verify(message, signature, pk);
        }

    private:
        XmssFast _xmss;
    };

    std::string EMSCRIPTEN_KEEPALIVE _bin2hstr(const std::vector<unsigned char> &input) {
        return bin2hstr(input, 0);
    }

    std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE _hstr2bin(const std::string &input) {
        return hstr2bin(input);
    }

    std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE _str2bin(const std::string &str) {
        return str2bin(str);
    }

    std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE _mnemonic2bin(const std::string &mnemonic)
    {
        return mnemonic2bin(mnemonic);
    }

    std::string EMSCRIPTEN_KEEPALIVE _bin2mnemonic(const std::vector<unsigned char> &vec)
    {
        return bin2mnemonic(vec);
    }

    std::string EMSCRIPTEN_KEEPALIVE _getHashFunction(const std::vector<unsigned char> &address)
    {
        if (address.size()<QRLDescriptor::getSize())
        {
            return "Invalid address";
        }

        auto descr = QRLDescriptor::fromBytes(address[0], address[1], address[2]);

        switch(descr.getHashFunction())
        {
            case eHashFunction::SHA2_256:
                return "SHA2_256";
            case eHashFunction::SHAKE_128:
                return "SHAKE128";
            case eHashFunction::SHAKE_256:
                return "SHAKE256";
        }

        return "Not recognized";
    }

    std::string EMSCRIPTEN_KEEPALIVE _getSignatureType(const std::vector<unsigned char> &address)
    {
        if (address.size()<QRLDescriptor::getSize())
        {
            return "Invalid address";
        }

        auto descr = QRLDescriptor::fromBytes(address[0], address[1], address[2]);

        switch(descr.getSignatureType())
        {
            case eSignatureType::XMSS:
                return "XMSS";
        }

        return "Not recognized";
    }

    uint8_t EMSCRIPTEN_KEEPALIVE _getHeight(const std::vector<unsigned char> &address)
    {
        if (address.size()<QRLDescriptor::getSize())
        {
            return 0;
        }

        auto descr = QRLDescriptor::fromBytes(address[0], address[1], address[2]);

        return descr.getHeight();
    }

    bool EMSCRIPTEN_KEEPALIVE _validateAddress(const std::vector<unsigned char> &address)
    {
        return QRLHelper::addressIsValid(address);
    }

    std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE _sha2_256(const std::vector<unsigned char> &data)
    {
        return sha2_256(data);
    }

    using namespace emscripten;

    EMSCRIPTEN_BINDINGS(my_module) {
        register_vector<unsigned char>("VectorUChar");
        function("bin2hstr", &_bin2hstr);
        function("hstr2bin", &_hstr2bin);
        function("str2bin", &_str2bin);

        function("mnemonic2bin", &_mnemonic2bin);
        function("bin2mnemonic", &_bin2mnemonic);

        function("getHashFunction", &_getHashFunction);
        function("getSignatureType", &_getSignatureType);
        function("getHeight", &_getHeight);

        function("validateAddress", &_validateAddress);
        function("sha2_256", &_sha2_256);

        class_<XmssWrapper>("Xmss")
                .constructor<TSEED, unsigned char>()
                .function("getPK", &XmssWrapper::getPK)
                .function("getSK", &XmssWrapper::getSK)
                .function("getSeed", &XmssWrapper::getSeed)
                .function("getExtendedSeed", &XmssWrapper::getExtendedSeed)
                .function("getHeight", &XmssWrapper::getHeight)

                .function("getRoot", &XmssWrapper::getRoot)
                .function("getPKSeed", &XmssWrapper::getPKSeed)
                .function("getSKSeed", &XmssWrapper::getSKSeed)
                .function("getSKPRF", &XmssWrapper::getSKPRF)

                .function("getAddress", &XmssWrapper::getAddress)

                .function("getIndex", &XmssWrapper::getIndex)
                .function("setIndex", &XmssWrapper::setIndex)

                .function("sign", &XmssWrapper::sign)
                .class_function("verify", &XmssWrapper::verify)
        ;
    }
}