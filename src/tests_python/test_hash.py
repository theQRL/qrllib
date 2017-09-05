# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function
from unittest import TestCase
import binascii

from pyqrlfast import pyqrlfast


class TestHash(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestHash, self).__init__(*args, **kwargs)

    def test_addr_to_byte(self):
        # TODO: Create a few handy classes to deal with these things
        tmp = b''
        tmp += b'\x00\x11\x22\x33'
        tmp += b'\x44\x55\x66\x77'
        tmp += b'\x88\x99\xAA\xBB'
        tmp += b'\xCC\xDD\xEE\xFF'
        tmp += b'\x10\x21\x32\x43'
        tmp += b'\x14\x25\x36\x47'
        tmp += b'\x18\x29\x3A\x4B'
        tmp += b'\x1C\x2D\x3E\x4F'

        # Create array and move bytes into it
        addr_in = pyqrlfast.uint32CArray(8)
        pyqrlfast.memmove(addr_in, tmp)

        # Prepare buffer to receive data
        bytes_out = pyqrlfast.ucharCArray(32)

        # Run function
        pyqrlfast.addr_to_byte(bytes_out, addr_in.cast())

        # Check results
        hex_out = binascii.hexlify(pyqrlfast.cdata(bytes_out, 32))
        self.assertEqual(hex_out, '3322110077665544bbaa9988ffeeddcc43322110473625144b3a29184f3e2d1c')
