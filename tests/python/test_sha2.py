# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function
from unittest import TestCase

from pyqrllib import pyqrllib


class TestSha2_256(TestCase):
    sha2_input1 = 'hello'
    sha2_expected_result1 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    sha2_input2 = 'hello-qrl'
    sha2_expected_result2 = '4ad6ad6c9ee6d2e52ebe4d635aa04052b7014e5e2e6b0de36da7648fac147703'

    def __init__(self, *args, **kwargs):
        super(TestSha2_256, self).__init__(*args, **kwargs)

    def check_sha_result(self, data_text, expected):
        hex_in_before = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        data_out = pyqrllib.sha2_256(pyqrllib.str2bin(data_text))

        # This is just to keep as an example. Things could be compared without converting to hex
        hex_in = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        hex_out = pyqrllib.bin2hstr(data_out)

        self.assertEqual(hex_in_before, hex_in)
        self.assertEqual(expected, hex_out)

    def check_sha_n_result(self, data_text, expected, count):
        hex_in_before = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        data_out = pyqrllib.sha2_256_n(pyqrllib.str2bin(data_text), count)

        # This is just to keep as an example. Things could be compared without converting to hex
        hex_in = pyqrllib.bin2hstr(pyqrllib.str2bin(data_text))
        hex_out = pyqrllib.bin2hstr(data_out)

        self.assertEqual(hex_in_before, hex_in)
        self.assertEqual(expected, hex_out)

    def test_check_sha2_256(self):
        self.check_sha_result(self.sha2_input1, self.sha2_expected_result1)
        self.check_sha_result(self.sha2_input2, self.sha2_expected_result2)

    def test_sha_n_result(self):
        self.check_sha_n_result("This is a test X",
                                "a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b", 1)
        self.check_sha_n_result("This is a test X",
                                "3be2d7e048d22de2c117465e5b4b819e764352680027c9790a53a7326d62a0fe", 16)
