#include <emscripten.h>
#include <emscripten/bind.h>
#include <iostream>
#include <xmssFast.h>
#include <misc.h>
#include <wordlist.h>
#include <memory>
#include <future>

namespace {

    class XmssWrapper
    {
    public:
        XmssWrapper(const std::vector<unsigned char> &seed, unsigned char height)
        {
            _xmss= std::async(std::launch::async,  [seed, height]()
            {
                return std::make_shared<XmssFast>(seed, height);
            });
        }

        bool willBlock() {    return _xmss.wait_for(std::chrono::seconds(0)) != std::future_status::ready;  }

        TSIGNATURE sign(const TMESSAGE &message)    {   return _xmss.get()->sign(message);     }

        TKEY getSK() {  return _xmss.get()->getSK(); }
        TKEY getPK() {  return _xmss.get()->getPK(); }
        TSEED getSeed() {  return _xmss.get()->getSeed(); }
        int getHeight() {  return _xmss.get()->getHeight(); }

        TKEY getRoot() {  return _xmss.get()->getRoot(); }
        TKEY getPKSeed() {  return _xmss.get()->getPKSeed(); }
        TKEY getSKSeed() {  return _xmss.get()->getSKSeed(); }
        TKEY getSKPRF() {  return _xmss.get()->getSKPRF(); }

        std::string getAddress() {  return _xmss.get()->getAddress("Q"); }

        unsigned int getIndex() {  return _xmss.get()->getIndex(); }
        unsigned int setIndex(unsigned int new_index) {  return _xmss.get()->setIndex(new_index); }

        static bool verify(const TMESSAGE &message,
                           const TSIGNATURE &signature,
                           const TKEY &pk)
        {
            return XmssFast::verify(message, signature, pk);
        }

    private:
        std::future<std::shared_ptr<XmssFast>> _xmss;
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

    using namespace emscripten;

    EMSCRIPTEN_BINDINGS(my_module) {
        register_vector<unsigned char>("VectorUChar");
        function("bin2hstr", &_bin2hstr);
        function("hstr2bin", &_hstr2bin);
        function("str2bin", &_str2bin);

        function("mnemonic2bin", &_mnemonic2bin);
        function("bin2mnemonic", &_bin2mnemonic);

        class_<XmssWrapper>("Xmss")
                .constructor<TSEED, unsigned char>()

                .function("willBlock", &XmssWrapper::willBlock)

                .function("getPK", &XmssWrapper::getPK)
                .function("getSK", &XmssWrapper::getSK)
                .function("getSeed", &XmssWrapper::getSeed)
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