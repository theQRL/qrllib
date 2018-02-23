# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function
from unittest import TestCase

from pyqrllib import pyqrllib


class TestXmssPool(TestCase):
    # sha2_input1 = 'hello'
    # sha2_expected_result1 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    # sha2_input2 = 'hello-qrl'
    # sha2_expected_result2 = '4ad6ad6c9ee6d2e52ebe4d635aa04052b7014e5e2e6b0de36da7648fac147703'

    def __init__(self, *args, **kwargs):
        super(TestXmssPool, self).__init__(*args, **kwargs)

    def test_pool(self):
        baseseed = pyqrllib.ucharVector(48, 0)
        pool = pyqrllib.XmssPool(baseseed, 6, 0, 3)
        self.assertFalse(pool.isAvailable())
        self.assertEqual(pool.getCurrentIndex(), 0)

        xmss = pool.getNextTree()
        self.assertEqual("0103002dcc3803df4475334b29eaa2516d1a9b36bc19eed0542cfbb501bf8de95d939b"
                         "25510d9876c7845b4694441bdc0e2be51f3d3f87f0c7775893845f25d49f9ef1",
                         pyqrllib.bin2hstr(xmss.getPK()))

        xmss = pool.getNextTree()
        self.assertEqual("010300be9caeafe11fa52edf722063c18616d6d0c6c30dba3e2c9369a6d9260f76818b"
                         "c424a1b6db5f26ef01ffa4aac8a08440d6a569bc56180b06f51b6ff6e4cc1b2e",
                         pyqrllib.bin2hstr(xmss.getPK()))

        xmss = pool.getNextTree()
        self.assertEqual("0103005deb91b1d311ecc8c6954e22f3e140ff3e6c04e40cad50c940e60abba3cf766a"
                         "5db9f39f58e532bea6765e4530cb581db1d6afbb7c05da3261ca4db21177afc5",
                         pyqrllib.bin2hstr(xmss.getPK()))

        xmss = pool.getNextTree()
        self.assertEqual("010300ea15c686e7b9691b8bac52ee4d0ed33bd75ec600f55b4476b857858460c2c983"
                         "90712040a5e03bca7a46715a90270ac2f8db8694ffa943091edb9018fa1dda04",
                         pyqrllib.bin2hstr(xmss.getPK()))
