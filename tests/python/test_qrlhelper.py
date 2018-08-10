# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


from __future__ import print_function

from unittest import TestCase

from pyqrllib import pyqrllib


class TestHelper(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHelper, self).__init__(*args, **kwargs)

    def test_empty(self):
        self.assertFalse(pyqrllib.QRLHelper.addressIsValid(b''))
