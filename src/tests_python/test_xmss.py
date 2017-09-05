# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function

from time import sleep
from unittest import TestCase

from pyqrlfast import pyqrlfast


class TestHash(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHash, self).__init__(*args, **kwargs)

    def test_xmss(self):
        HEIGHT = 6

        seed = pyqrlfast.ucharVector(32, 0)
        xmss = pyqrlfast.Xmss(seed=seed, height=HEIGHT)

        print("Seed", len(seed))
        print(pyqrlfast.vec2hexstr(seed, 32))

        print("PK  ", len(xmss.getPK()))
        print(pyqrlfast.vec2hexstr(xmss.getPK(), 32))

        print("SK  ", len(xmss.getSK()))
        print(pyqrlfast.vec2hexstr(xmss.getSK(), 32))

        self.assertIsNotNone(xmss)
        self.assertEqual(xmss.getHeight(), HEIGHT)

        message = pyqrlfast.ucharVector([i for i in range(32)])
        print("Msg ", len(message))
        print(pyqrlfast.vec2hexstr(message, 32))

        # TODO: At the moment, sign is hardcoded for message length 32
        # Sign message
        signature = bytearray(xmss.sign(message))

        print("Sig ", len(signature))
        print(pyqrlfast.vec2hexstr(signature, 128))

        print('----------------------------------------------------------------------')
        # Verify signature
        self.assertTrue(xmss.verify(message,
                                    signature,
                                    xmss.getPK(),
                                    xmss.getHeight()))
