# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function

from unittest import TestCase

from pyqrllib.pyqrllib import ucharVector, bin2hstr, hstr2bin
from pyqrllib.dilithium import Dilithium


class TestDilithium(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestDilithium, self).__init__(*args, **kwargs)

    PK1_HSTR = "6080a00cb958ed2dfe03e33c72a0ab60e76f341bf730d08922cfe9dbb0a4ac9b" \
               "2cb47d7adc0e38671fce3bcd4683da331b513666ff5d8adf28576fef7cb474cb" \
               "3a206f7806023989798f98c5bac85db1fd62e186ccca8db54cbfc88943bdf4ec" \
               "f66c1f95108444603b3f6d88a5de08999f4b3c72d04ca2910efc6feea5e1da25" \
               "d7b449ce554f6823e4dce0a387a3af957a8697abf641fcd163a6b5fe56fa67eb" \
               "13977cb76bace789ce5ae0f6878f06f26e610de102b8549323e7e5baa5ae5569" \
               "c0bed78e1faf857b2b005fdad1a7c2297084739a42ae2b0c0fb870301dc01401" \
               "ed3cf698f2460cd542c54181781f32d41067c3743d0cf5dbf47336203f7aa93f" \
               "e5701b54566f625e736f0607580ea11974bb23d36c3afc7c1fb1e22545b70edb" \
               "cee8e61e856a6195b8bbdd596530d87f7e376134fb11740469f94b91340b6425" \
               "49a0bbfa0c0349a8a53eb1184771ba2fb3c1a984ee2e52a7026d5832ea98b927" \
               "a850166870880fa18710588d1d0a4a920e4592885ea0da46fa0a0eedb3d15384" \
               "d4f990f2dc3efa3db066a5f30d0a5de731710bdc9861cfc00f4d14bcb04fec29" \
               "790e4bfcc992f2a68c8e2cb69c227a9aee98536e74f463b938e1910d0f2cfa6a" \
               "e876b56464210b4bed963be8e6fec6e119d314482933d3be6f505cacc0d5baae" \
               "c26c12a027c8c33358b0022b53f8bc395edaa37b55ead5992ab1e5cbc69b2eda" \
               "03c7e18c510abdb8d8620ab2bf555054cb873c55df83e190e35ffc0133161e2d" \
               "801acbb92d3fa367dc817363bf45acc53e80d8f6e13f6a5a03e967caef84de70" \
               "b0e78b4db735731bf8a9412a2645b33a0f6e8c0d2f9ddef178fa016b32ced798" \
               "39e9a57118f8d2058c859ae81c17017b9d5964068f66618181254cf465c5b98e" \
               "6151f750e6184e01b9ab57fc3143e2edbcce39fecb8d231db1396a4cb08fe054" \
               "1d02fed012a88329f3f2d4a8f48796646dc462442d4578a89c9147e40296f3aa" \
               "68e801e44e58bf85a82ca0707272fae9d11a70c9d6b98a568ad38e39c845b863" \
               "c2058b141dfb6d5bcab2af4df9a5daf0684d13450589cdbd52d1f4a82eb1a54a" \
               "18c3b837f24fc2df8fc99d63a5baa29acdb21a3dd7872a9f85d16226a3a13505" \
               "8711ba2c5056439fbc0842db47d1664396aad47af078dc381ccc06cc86f92d40" \
               "42ea77fa4d6fdcb5cc6f711b74a023830298aa8d063d08dae5d317dbcfea3a73" \
               "8a15c7c63924ae17ed5bd3cb914a474e3d1b33f413ee400ba9768f74c2e6b7cf" \
               "d38189844d9073d23379c9a01c9287029df41393c110c2080a3631e4a3c2013a" \
               "64ebca16cf78a24e8a31be13f4ad50242410b51c341350bd255f3b85a0ae470e" \
               "0ede255dc5c04773d4fce61a67f5974cdeb7a8dd9dc9ce0b0c879d20714d474a" \
               "d129c3c52c3fbda5284720955b5045d336983f2e056a680e3ca887f7dc489df7" \
               "d65ad6e11fe9478bda9b3f27de6652cef4d114eae6d12f5a5d25bb4633adbdab" \
               "59208f9b6e382b83c1a63f349fa3a0951c0db4fdc7194f1c955c3637cea1c56f" \
               "9d0c4c1a7be3140e5c833ccd7c0fcd6b403400c33dc40409e978aa08424d7a81" \
               "a298c67e4833ac51ebb8f144bdab80652e48af8ee3fb89255dc0a3bbd439902e" \
               "b584019a20f84593dfe542f511dea80bfee4973f7b5d56c2767de99b847e97e7" \
               "82c6612b9d6bded83b8bd0391ae312cf44134fab832a14048bf5d068d8b717bd" \
               "1541ba40d3cdbc32fa6807cf078620a2efc5e8b273d50d40cf1a6f1298a1067d" \
               "f7ad2b2bb58d4fbef8adc7da8fb19d1d5737424c3dc2cef106fcd4f7f2b16ebe" \
               "c2276c6beaa18fcf1d028298a6d51e699f9a5562cf22ba1ed57f38a279de3599" \
               "cf63688279ec0c8c9ba86f482159162ebf12feef9fca686cd7909f6c64000a5f" \
               "7fec0472c350b4dbbbc228aba153674dcfc13c0fae15dd7a17b6a85b2f0d73b9" \
               "0dcfc25886d00b691a4a1ec3619983d9447b91fccb0aacf5590d7dc5dfab8b9a" \
               "1b5d8920eeb3f447755bf6177f3ded97315c639e25b8902ca04f6bdb0cf6591b" \
               "a21f412da4a9eaa48c03949c696cb2f2071592c5ba5d39be65962c1409b3e70b"

    SK1_HSTR = "6080a00cb958ed2dfe03e33c72a0ab60e76f341bf730d08922cfe9dbb0a4ac9b" \
               "acac8d6f3a11625296afe8f7123cd0e7a2e5caa6433448c37e3c161cd834cbe8" \
               "8df2f82ea82c69993debb0c78afec12e0203d8ea566960640e1be33d1c70c25d" \
               "a8364eed459a4df0bd7576ab05678f48aaa12573379190a62747000a28923020" \
               "544920981a50a74152a67735a055671906350019407a456849918666312a5327" \
               "247aa1627752a09840457900655044156a3289553808553915205a3a93800282" \
               "374766917362417a5574917a38544980a374355979382294654120014a863238" \
               "0394876aa0054939786129670491817942900361396445775812a69676a42014" \
               "69732490a636928563a821086803012a4819628565925171108740238a500929" \
               "5627395030a7990285355836a32870940a5580366120940a5197666a58892177" \
               "28851504491274806798414a4047101876799972930424593169927805a5a023" \
               "3431869666915900a0a49864645a814546891924309505366155301836268755" \
               "099096159a6a802557794405108754050222885081a42551914915446770a903" \
               "a1a36a4945aa57158774aa35a3a7398567929a196871229a880a021525a764a4" \
               "72770665006383205a63851672aa1734187359687453534433414506009a7857" \
               "88a828868a865985a8a233109268356497985537500a1692476362536112812a" \
               "82693413170a66451309a839677430283042504683a5a3562148556161548100" \
               "99031696900521a920863064580a506791194755583a9483a099296653979615" \
               "8a9356a30a1297724997880153490a87a35a0523a096124496977a155a478460" \
               "30754774717aa73036a062901a0775715a29708309286483841533a456451781" \
               "459563396a42a6939981a8568576aa626a7611a818211462a1a183340243662a" \
               "a855073238740485752560797a521604a8389151952192659000819218a81a34" \
               "96809108917110356741496048644029848651986741646375a0123972837029" \
               "a33496a3657799743aa996093942200a4a957002360211304344a31609974577" \
               "79313349992a159845137944a3968a61a73166862472226a39a74587a65a6059" \
               "211a5623a038007715200459586a408a82834061a46468265a2459238a976349" \
               "51568733751296407460a291658764040408a85155a389182705536502379641" \
               "06014050882907908105a903a845aa4291697911379004978a0900a7a079a895" \
               "879a2441326289596224458681881a95342a7828279745a38990473902784562" \
               "8a9832018525141829714129089013721184aa206a2332847259888570301326" \
               "7903654180172935a37355023a848910952280309a168617495381377637a52a" \
               "9139043679845573650904569880907703593960702a84a8aa70aa4444445a26" \
               "296261004334516a8836a5a358453143405a7785613746724aa771996922a2a0" \
               "766aa573a588822684794912120848020704537444450a68a7277565981045a2" \
               "85463614382089818721944a1606219858065573602875a245a123a752225381" \
               "042436948010a52328453a75980267379937918a5a5482367268880a98168a49" \
               "696803559a23993a7952564542599615170061040374214499a770aa5a383440" \
               "9115061a397a437356043956000670413a1a25008045080a041a54aa87231836" \
               "37a292a38a3a83006a76112504708a5124057061a22a40001891a36132763225" \
               "6a1292187378897469a0a8a83111a2342bc1f1cd7ed8cbc01c30b331f88f5746" \
               "6d5c0e111bb4c56b8069e20347fa5fb63cde3b6aa11c82503bb7aed83a1ad680" \
               "361db94d3eb3c8cd4bdc75c30b4b2f8ad46ac2e94a35ccb1cf12c5da7f977cea" \
               "7799c870d153a7e9965ec94c23c1256721de61a7c1ea2f817a2d44bad3a01903" \
               "8d365e420a35d387cb237e2e5d6c7fb2dd10b1a7c0e7cd2c124b983d64f4e04c" \
               "2e9ffafb0600956591f6b36176223105ce024ea256305c839b538e642fe94141" \
               "eae4fbbef507d3cd2a96bd847e475f621399eddc594a0b8b9378dfed75a14b47" \
               "5bc9f893c8ce5d51e379611bcc91bd827160cfd1e3fcde61d188c2e6d71bf900" \
               "8b9ec8c8780f4d3ebab0b9bbb33d804f8f0ab9afb93786ea3d0c94d5ba4baeae" \
               "991e515953176e972cca742f71fe638918579dd4856e54903dee32ea33e8cc3c" \
               "2d2734f076315099527fabc16942803cda01018d33cebc53604e2a6560e997ff" \
               "e40f3046e8621b1b909bf861d94769ec5a9e0ffae6370f227b5db33d6f633cb8" \
               "430b1558ad10e472921da7f92d73e34cb245df3ad4b5319aea6e8481e0c8236e" \
               "993816cdb110b38b43cee5b88075f5fac6c5e64cdc79503a65ad0e139f20d12f" \
               "c13b9a8c1c8a0d65232ea364162b767dde8ab1849327306568c68936be6346e3" \
               "cd2800ef7b1dc7f8af552250998c74dd74d7784c3e51e231f22783549fd94d1a" \
               "31abdaabce402d4c69b3be34340b479b840e15ab28474eac68547516ea721958" \
               "90326b8bffbef3761c31a8ca48a957223f993d9ae9c52405671244d7ef9044c1" \
               "632a904ca9d424e94d0b6d9c331277f73c41f3bd65a62de53d9bbf73a4c8b9cf" \
               "9c7b84b3497ebfacc1fba14187c58e41add4ef846785029e8c86d32841d5a997" \
               "9b36db22732855738155445bcc3048fd684eff55228d6e1d7d35a28f84fb9c1f" \
               "41f4fd718bb78ed89f076e5e47fd2428111111ea2701e1b5ab7157e6e31d2287" \
               "18902053525c315e5c16c364154c71b24fd29b9498755cb35ad3201a67b25bf4" \
               "196da617f30f025a22a8aaea6c94aed587c8a63066da6267f03579b7ca44de30" \
               "de26590f81f9eae9b7081b8a9608e1fa773fc971650bfb9210c0d3c7f1318544" \
               "3d6b457881188ad2731bbaf81fde2d29d06e405806e7c1705e426b0000cf6cba" \
               "100051ed578d60d28022c9eb05b2b2a3765f6fa1ef01b32445f6458fc05242e0" \
               "bb1ec05d69a6180da11c6c591b462b5acc641bc4dfdcfb619755cd7380c9e6f8" \
               "84a1f1054b71cebde4e1bb50bb6d8f71134431dcd6c8f6588029f007f35b469c" \
               "fffd41a78835c69b8385465d26a433af0b47498f1e636f8abc1af4ac86af6997" \
               "026a95cf104652dff5c76599dc9f40f40806c21b05ef27aec028be549fb1b792" \
               "33b02034b2ae6b3cda125eb1c339c4283de0d2d0d2c82e681096bb75326271d6" \
               "204a7849a7d63ac1430545a13abf92c9ff7557c5c8afec0ff8c2af4c7d4d594a" \
               "ff74a5e3089bbf98a21cc78c56be690c716c9465f4e44bb88ed3114268e1fbea" \
               "cd08026d979f0bd9391b52ce6c1a586df17ca8e131b9017c2bd233c2943b5973" \
               "749c00591a6bf17c3aaf51a1156ff4bd5efe191d1c279cc9d35642b96c6b3ed1" \
               "8a2e5f086e5ee3d04437d7aa851ce31ff7645de359ac87c6a5fc1b1d68def0d6" \
               "b0f8e8e3d67368ed510dbd049d3c1e6c3760ec5da375498aa50de628431455f3" \
               "a4f8965fd4fa446864e7d5aa1c716196b2fd4e001081837eb7d62edb5f360287" \
               "f6f05684623dacaf9fae61960bb134d37926dc73a8b9b4d887281d7745c62542" \
               "7ef4ea59270b87d40c035c770c4be454206cc76d3bfe9a35716363dd180a8060" \
               "2062d9a1458bfb99ff6f5fdc86e09b8637f30b0a776d63512d4e2dd458ef1fd3" \
               "c9ab244f22fa3981bcf9e8d1ce77cb49c5b16b38136bd6c32cc1cb623c5c56b3" \
               "dac422d6b61436b29033d866599b1de6ca73c69fdd7ce602cf5f1160dbd25e2b" \
               "922bba8b7fc82e427e27dfc4067e9f470b2a753204d662c77448f5cd027381e7" \
               "a144ea51414e950ec4737170d1a0646f7c1f8f6813446d08d1666f4915153e66" \
               "c30e524473a960ab8a9705ba7f8ef106e65a6386530b5e9e148e5cd2e0373ca6" \
               "43920839d114e24d7be40fa91c49f578874db1b8f6b80d069fc08fbeea789d73" \
               "0d1ff4d08e01d5df91d7f4dfd673dc95a79baa9ed9eae797c1f7e08f6bcef693" \
               "b876fb8933523c4ffbeab8ca4078cb82511a06e3af55f45839b286fefb04b0a3" \
               "ec24918748f54426b804843f09a90378a6ce7702646d8db8ddad0939ce1a74e2" \
               "73fcf9f47becc39fb245a53baebb1645c34e978f543d30554a401edd0fe23e45" \
               "cef20563e9a79c5e4edb9efa3fafd6d0b47c98db4608ac5f6416833048600b8e" \
               "566a4d2ecbdec9fd7f35448127f8fa2a3cdabcf77002ec2412c185181972e9eb" \
               "15661d2ba1343718ed64898f7203a5207c5a9c6054effd2c0504db8ec27f0263" \
               "4dac2f4437ba266ebc597e47137681c20e0a127ec62414d395f7868efee3e261" \
               "7a5c48e45b7b257f1dd3325f1d8f7ca255c6bfa68039c0b33a8f0f3cfa943eb8" \
               "7bfa59c225870e4b781810f0c101075b82c9ee9e6052594f25a389ae6464cd99" \
               "1a03d3b5b4151e7eba382c5a66434f4be295199f03d6889957528e8e95177f62" \
               "2da622a7e7ec6192f6d7ed8d42b701814b95c76caa3850c6cc6dbfb7255e6b1f" \
               "51a84faf7d2706492175c794167583f6310cbb0f269006980f9448356854cdcb" \
               "a67d7c11f69ae88200e0199ab4541296f7bfd5f016f3aed0935892cabeda5a13" \
               "f95eea3064fd86e04630c50802b8a15c20a8a76943009e87566958187a292d4a" \
               "b883b17b458f5990ebc9b9d28596fb72823270cf3e9e1f38c404957b42e86653" \
               "2d24ce51b7dd937612d2d03f226a30b91a2968c0524234675c6ac46405d3a4f3" \
               "2f99edf913b7701a50a8ed5284ae7bd80b1177f058baaaca586ae6fa6bca643f" \
               "1773c78f39c0bfab7ee500777668769f4991b185ef981a5d1e6ca6a6c6363187" \
               "634d95d8c4b8b5b631de97856fd70416cc2aebb4b2e110faf60b10aea01035e8" \
               "e77d9f9491ab95a355a76a1fffd027d068f293c3d315c4fd90afdfb493ba781e" \
               "4b485fbb1d1ccc2e0a8002a35ba540af38f3b3dc8642041ab31bc77add8d3aea" \
               "5974ee5c2265443538324094ae665ad9"

    def test_dilithium_reference(self):
        dilithium = Dilithium()

        self.assertEqual(1472, len(dilithium.getPK()))
        self.assertEqual(3504, len(dilithium.getSK()))

        message = bytes(b"This is a test")
        message_signed = dilithium.sign(message)
        data_out = ucharVector(len(message_signed))

        Dilithium.sign_open(data_out, message_signed, dilithium.getPK())

        message_out = Dilithium.extract_message(data_out)
        signature_out = Dilithium.extract_signature(data_out)

        self.assertEqual(2715, len(data_out))
        self.assertEqual(len(message_out), len(message_out))
        self.assertEqual(2701, len(signature_out))

        self.assertEqual(message, bytes(message_out))
        self.assertEqual(b"This is a test", bytes(message_out))

        print(bin2hstr(dilithium.getPK()))
        print(bin2hstr(dilithium.getSK()))


    def test_dilithium_reference2(self):
        pk = bytes(hstr2bin(self.PK1_HSTR))
        sk = bytes(hstr2bin(self.SK1_HSTR))

        dilithium = Dilithium(pk, sk)

        self.assertEqual(1472, len(dilithium.getPK()))
        self.assertEqual(3504, len(dilithium.getSK()))

        message = bytes(b"This is a test")
        message_signed = dilithium.sign(message)
        data_out = ucharVector(len(message_signed))

        Dilithium.sign_open(data_out, message_signed, dilithium.getPK())

        message_out = Dilithium.extract_message(data_out)
        signature_out = Dilithium.extract_signature(data_out)

        self.assertEqual(2715, len(data_out))
        self.assertEqual(len(message_out), len(message_out))
        self.assertEqual(2701, len(signature_out))

        self.assertEqual(message, bytes(message_out))
        self.assertEqual(b"This is a test", bytes(message_out))
