# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function

from time import sleep, time
from unittest import TestCase

import pytest

from pyqrllib import pyqrllib


class TestXmssBasic(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestXmssBasic, self).__init__(*args, **kwargs)

    def test_xmss(self):
        HEIGHT = 6

        seed = pyqrllib.ucharVector(48, 0)
        xmss = pyqrllib.XmssBasic(seed, HEIGHT)

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
        # print(end - start)

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
            xmss = pyqrllib.XmssFast(seed, HEIGHT, pyqrllib.SHA3)

    def test_xmss_exception_verify(self):
        message = pyqrllib.ucharVector(48, 0)
        signature = pyqrllib.ucharVector(2287, 0)
        pk = pyqrllib.ucharVector(48, 0)

        with pytest.raises(ValueError):
            pyqrllib.XmssFast.verify(message, signature, pk)
