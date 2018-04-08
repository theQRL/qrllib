# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


from __future__ import print_function
from unittest import TestCase

from pyqrllib import pyqrllib
from pyqrllib.pyqrllib import mnemonic2bin, bin2mnemonic


class TestMisc(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMisc, self).__init__(*args, **kwargs)

    def test_data_to_hex1(self):
        hexstring = pyqrllib.bin2hstr(b'\x00\x11\x22\x33', 0)
        self.assertEqual(hexstring, '00112233')

    def test_data_to_hex2(self):
        hexstring = pyqrllib.bin2hstr('test', 0)
        self.assertEqual(hexstring, '74657374')

    # def test_data_to_hex2(self):
    #     bin = mnemonic2bin('absorb')
    #     self.assertEqual(tuple([1, 0]), bin)

    def test_mnemonic1(self):
        bin = mnemonic2bin('aback absorb')
        self.assertEqual(tuple([0, 0, 16]), bin)

    def test_mnemonic2(self):
        bin = mnemonic2bin('absorb absorb')
        self.assertEqual(tuple([1, 0, 16]), bin)

    def test_mnemonic3(self):
        bin = mnemonic2bin('absorb absorb')
        tmp_mnemonic = bin2mnemonic(bin)
        self.assertEqual('absorb absorb', tmp_mnemonic)

    def test_mnemonic4(self):
        bin = mnemonic2bin('absorb')
        tmp_mnemonic = bin2mnemonic(bin)
        self.assertEqual('absorb', tmp_mnemonic)

    def test_exception(self):
        i = 0
        try:
            x = pyqrllib.hstr2bin('Z')
        except Exception as e:
            i = 1
        self.assertEqual(i, 1)

        i = 0
        try:
            x = pyqrllib.hstr2bin('Z0')
        except Exception as e:
            i = 1
        self.assertEqual(i, 1)
