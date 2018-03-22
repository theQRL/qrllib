# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function

from time import time
from unittest import TestCase

import pytest

from pyqrllib import pyqrllib


class TestXmssBasic(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestXmssBasic, self).__init__(*args, **kwargs)

    def test_xmss_creation_height4(self):
        HEIGHT = 4
        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssBasic(seed, HEIGHT, pyqrllib.SHAKE_128, pyqrllib.SHA256_2X)

        expected_address = "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897"
        expected_PK = "010200c25188b585f731c128e2b457069e" \
                      "afd1e3fa3961605af8c58a1aec4d82ac" \
                      "316d3191da3442686282b3d5160f25cf" \
                      "162a517fd2131f83fbf2698a58f9c46a" \
                      "fc5d"

        self.assertEqual(expected_PK, pyqrllib.bin2hstr(xmss.getPK()))
        self.assertEqual(expected_address, pyqrllib.bin2hstr(xmss.getAddress()))

        tmp_addr = pyqrllib.QRLHelper.getAddress(xmss.getPK())
        self.assertEqual(expected_address, pyqrllib.bin2hstr(tmp_addr))

        descr = pyqrllib.QRLHelper.extractDescriptor(xmss.getPK())
        self.assertEqual(4, descr.getHeight())
        self.assertEqual(pyqrllib.SHAKE_128, descr.getHashFunction())

    def test_xmss_creation_height6(self):
        HEIGHT = 6
        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssBasic(seed, HEIGHT, pyqrllib.SHAKE_128, pyqrllib.SHA256_2X)

        expected_address = "0103008b0e18dd0bac2c3fdc9a48e10fc466eef899ef074449d12ddf050317b2083527aee74bc3"

        expected_PK = "010300859060f15adc3825adeec85c7483" \
                      "d868e898bc5117d0cff04ab1343916d4" \
                      "07af3191da3442686282b3d5160f25cf" \
                      "162a517fd2131f83fbf2698a58f9c46a" \
                      "fc5d"

        self.assertEqual(expected_PK, pyqrllib.bin2hstr(xmss.getPK()))
        self.assertEqual(expected_address, pyqrllib.bin2hstr(xmss.getAddress()))

        tmp_addr = pyqrllib.QRLHelper.getAddress(xmss.getPK())
        self.assertEqual(expected_address, pyqrllib.bin2hstr(tmp_addr))

        descr = pyqrllib.QRLHelper.extractDescriptor(xmss.getPK())
        self.assertEqual(6, descr.getHeight())
        self.assertEqual(pyqrllib.SHAKE_128, descr.getHashFunction())

    def test_xmss(self):
        HEIGHT = 6

        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssBasic(seed, HEIGHT, pyqrllib.SHAKE_128, pyqrllib.SHA256_2X)

        # print("Seed", len(seed))
        # print(pyqrllib.bin2hstr(seed, 48))
        #
        # print("PK  ", len(xmss.getPK()))
        # print(pyqrllib.bin2hstr(xmss.getPK(), 48))
        #
        # print("SK  ", len(xmss.getSK()))
        # print(pyqrllib.bin2hstr(xmss.getSK(), 48))

        self.assertIsNotNone(xmss)
        self.assertEqual(xmss.getHeight(), HEIGHT)

        message = pyqrllib.ucharVector([i for i in range(32)])
        # print("Msg ", len(message))
        # print(pyqrllib.bin2hstr(message, 48))

        # Sign message
        signature = bytearray(xmss.sign(message))

        # print("Sig ", len(signature))
        # print(pyqrllib.bin2hstr(signature, 128))
        #
        # print('----------------------------------------------------------------------')
        # Verify signature
        start = time()
        for i in range(1000):
            self.assertTrue(pyqrllib.XmssBasic.verify(message,
                                                      signature,
                                                      xmss.getPK()))
        end = time()
        print(end - start)

        # Touch the signature
        signature[100] += 1
        self.assertFalse(pyqrllib.XmssBasic.verify(message,
                                                   signature,
                                                   xmss.getPK()))
        signature[100] -= 1
        self.assertTrue(pyqrllib.XmssBasic.verify(message,
                                                  signature,
                                                  xmss.getPK()))

        # Touch the message
        message[2] += 1
        self.assertFalse(pyqrllib.XmssBasic.verify(message,
                                                   signature,
                                                   xmss.getPK()))
        message[2] -= 1
        self.assertTrue(pyqrllib.XmssBasic.verify(message,
                                                  signature,
                                                  xmss.getPK()))

    def test_xmss_exception_constructor(self):
        HEIGHT = 7
        seed = pyqrllib.ucharVector(48, 0)

        with pytest.raises(ValueError):
            xmss = pyqrllib.XmssFast(seed, HEIGHT, pyqrllib.SHAKE_128)

    def test_xmss_exception_verify(self):
        message = pyqrllib.ucharVector(48, 0)
        signature = pyqrllib.ucharVector(2287, 0)
        pk = pyqrllib.ucharVector(48, 0)

        self.assertFalse(pyqrllib.XmssFast.verify(message, signature, pk))

    def test_xmss_change_index_too_high(self):
        HEIGHT = 4
        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssFast(seed, HEIGHT, pyqrllib.SHAKE_128)

        with pytest.raises(ValueError):
            xmss.setIndex(20)

    def test_xmss_change_index_high(self):
        HEIGHT = 4
        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssFast(seed, HEIGHT, pyqrllib.SHAKE_128)

        with pytest.raises(ValueError):
            xmss.setIndex(16)

    def test_xmss_change_index_limit(self):
        HEIGHT = 4
        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssFast(seed, HEIGHT, pyqrllib.SHAKE_128)

        xmss.setIndex(15)
        self.assertEqual(15, xmss.getIndex())

    def test_xmss_change_index(self):
        HEIGHT = 4
        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssFast(seed, HEIGHT, pyqrllib.SHAKE_128)

        xmss.setIndex(0)
        self.assertEqual(0, xmss.getIndex())