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

    def test_mnemonic_words_odd_1(self):
        with self.assertRaises(ValueError):
            mnemonic2bin('absorb')

    def test_mnemonic_words_odd_2(self):
        with self.assertRaises(ValueError):
            mnemonic2bin('absorb bunny bunny')

    def test_mnemonic1(self):
        result = mnemonic2bin('aback absorb')
        self.assertEqual(tuple([0, 0, 16]), result)

    def test_mnemonic2(self):
        result = mnemonic2bin('absorb absorb')
        self.assertEqual(tuple([1, 0, 16]), result)

    def test_mnemonic3(self):
        long_mnemonic = "law bruise screen lunar than loft but franc strike asleep dwarf tavern dragon alarm " + \
                        "snack queen meadow thing far cotton add emblem strive probe zurich edge peer alight " + \
                        "libel won corn medal"
        exp_result = '7ad1e6c1083de2081221056dd8b0c142cdfa3fd053cd4ae288ee324cd30e027462d8eaaffff445a1105b7e4fc1302894'

        self.assertEqual(exp_result, pyqrllib.bin2hstr(mnemonic2bin(long_mnemonic)))

    def test_mnemonic4(self):
        bin = mnemonic2bin('absorb absorb')
        tmp_mnemonic = bin2mnemonic(bin)
        self.assertEqual('absorb absorb', tmp_mnemonic)

    def test_exception(self):
        with self.assertRaises(ValueError):
            pyqrllib.hstr2bin('Z')

        with self.assertRaises(ValueError):
            pyqrllib.hstr2bin('Z0')
