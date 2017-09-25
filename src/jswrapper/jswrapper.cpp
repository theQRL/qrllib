#include <emscripten.h>
#include <emscripten/bind.h>
#include <iostream>
#include <xmssFast.h>
#include <misc.h>
#include <xmss.h>

namespace {

    class XmssWrapper
    {
    public:
        XmssWrapper(const std::vector<unsigned char> &seed, unsigned char height) : _xmss(seed, height) {}

        TSIGNATURE sign(const TMESSAGE &message)    {   return _xmss.sign(message);     }

        TKEY getSK() {  return _xmss.getSK(); }
        TKEY getPK() {  return _xmss.getPK(); }
        TSEED getSeed() {  return _xmss.getSeed(); }
        int getHeight() {  return _xmss.getHeight(); }

        TKEY getRoot() {  return _xmss.getRoot(); }
        TKEY getPKSeed() {  return _xmss.getPKSeed(); }
        TKEY getSKSeed() {  return _xmss.getSKSeed(); }
        TKEY getSKPRF() {  return _xmss.getSKPRF(); }

        unsigned int getIndex() {  return _xmss.getIndex(); }
        unsigned int setIndex(unsigned int new_index) {  return _xmss.setIndex(new_index); }

        static bool verify(const TMESSAGE &message,
                           const TSIGNATURE &signature,
                           const TKEY &pk,
                           unsigned char height)
        {
            return XmssFast::verify(message, signature, pk, height);
        }

    private:
        XmssFast _xmss;
    };

    std::string EMSCRIPTEN_KEEPALIVE _bin2hstr(std::vector<unsigned char> input) {
        return bin2hstr(input, 0);
    }

    std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE _hstr2bin(std::string input) {
        return hstr2bin(input);
    }

    std::vector<unsigned char> EMSCRIPTEN_KEEPALIVE _str2bin(std::string str) {
        return str2bin(str);
    }

    using namespace emscripten;

    EMSCRIPTEN_BINDINGS(my_module) {
        register_vector<unsigned char>("VectorUChar");
        function("bin2hstr", &_bin2hstr);
        function("hstr2bin", &_hstr2bin);
        function("str2bin", &_str2bin);

        class_<XmssWrapper>("Xmss")
                .constructor<TSEED, unsigned char>()
                .function("getPK", &XmssWrapper::getPK)
                .function("getSK", &XmssWrapper::getSK)
                .function("getSeed", &XmssWrapper::getSeed)
                .function("getHeight", &XmssWrapper::getHeight)

                .function("getRoot", &XmssWrapper::getRoot)
                .function("getPKSeed", &XmssWrapper::getPKSeed)
                .function("getSKSeed", &XmssWrapper::getSKSeed)
                .function("getSKPRF", &XmssWrapper::getSKPRF)

                .function("getIndex", &XmssWrapper::getIndex)
                .function("sign", &XmssWrapper::sign)
                .class_function("verify", &XmssWrapper::verify)
        ;
    }

}