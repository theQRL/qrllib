# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function
from unittest import TestCase

from pyqrllib import pyqrllib


class TestShake128(TestCase):
    # Values obtained from https://emn178.github.io/online-tools/shake_128.html
    shake128_input1 = 'hello'
    shake128_expected_result1 = '8eb4b6a932f280335ee1a279f8c208a349e7bc65daf831d3021c213825292463'
    shake128_input2 = 'hello-qrl'
    shake128_expected_result2 = '50028af4e91b430a1ec24924edc707b0d24ab01be44ea5f5c5c111087e9aadcb'

    def __init__(self, *args, **kwargs):
        super(TestShake128, self).__init__(*args, **kwargs)

    def check_shake_result(self, data_text, expected):
        size_out = 32

        hex_in_before = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        data_out = pyqrllib.shake128(32, pyqrllib.str2bin(data_text))

        # This is just to keep as an example. Things could be compared without converting to hex
        hex_in = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        hex_out = pyqrllib.bin2hstr(data_out)

        self.assertEqual(hex_in, hex_in_before)
        self.assertEqual(hex_out, expected)

    def test_check_shake128(self):
        self.check_shake_result(self.shake128_input1, self.shake128_expected_result1)
        self.check_shake_result(self.shake128_input2, self.shake128_expected_result2)


class TestShake256(TestCase):
    # values obtained from https://emn178.github.io/online-tools/shake_256.html
    shake256_input1 = 'hello'
    shake256_expected_result1 = '1234075ae4a1e77316cf2d8000974581a343b9ebbc' \
                                'a7e3d1db83394c30f221626f594e4f0de63902349a' \
                                '5ea5781213215813919f92a4d86d127466e3d07e8be3'

    shake256_input2 = 'hello-1234'
    shake256_expected_result2 = '4a01ca14fd8468f2d2e3a0b3d7597731ad15501675' \
                                '3677807ed735b022a9944e61586a6378fc6ffe49e9' \
                                'e0e456f8e2bbfaa41330c5ae7005a2d24ac8f0597e60'

    def __init__(self, *args, **kwargs):
        super(TestShake256, self).__init__(*args, **kwargs)

    def check_shake_result(self, data_text, expected):
        # Move data into array
        hex_in_before = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        data_out = pyqrllib.shake256(64, pyqrllib.str2bin(data_text))

        # This is just to keep as an example. Things could be compared without converting to hex
        hex_in = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        hex_out = pyqrllib.bin2hstr(data_out)

        self.assertEqual(hex_in, hex_in_before)
        self.assertEqual(hex_out, expected)

    def test_check_shake256(self):
        self.check_shake_result(self.shake256_input1,
                                self.shake256_expected_result1)
        self.check_shake_result(self.shake256_input2,
                                self.shake256_expected_result2)
