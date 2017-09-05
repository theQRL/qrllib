# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function
from unittest import TestCase
import binascii

import sys

from pyqrlfast import pyqrlfast


class TestHash(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHash, self).__init__(*args, **kwargs)

    def test_xmss(self):
        seed = [i for i in range(32)]
        xmss = pyqrlfast.Xmss(seed=seed, height=10)

        self.assertIsNotNone(xmss)
        self.assertEqual(xmss.getHeight(), 10)

        # It is not necessary to use a bytearray, list would work
        msg = pyqrlfast.ucharVector(bytearray([66, 67, 69]))

        signature = bytearray(xmss.sign(msg))
        print(signature)
