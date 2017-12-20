# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function

import unittest
from unittest import TestCase

from pyqrllib.kyber import Kyber


class TestKyber(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestKyber, self).__init__(*args, **kwargs)

    def test_exchange_keys(self):
        alice = Kyber()
        bob = Kyber()

        # Alice sends her public key to Bob
        alice_public_key = alice.getPK()

        # Bob receives the public key, derives a secret and a response
        bob.kem_encode(alice_public_key)
        cypherText = bob.getCypherText()

        # Bob sends the cyphertext to alice
        valid = alice.kem_decode(cypherText)

        # Now Alice and Bob share the same key
        alice_key = alice.getMyKey()
        bob_key = bob.getMyKey()

        self.assertTrue(valid)
        self.assertEqual(alice_key, bob_key)


if __name__ == '__main__':
    unittest.main()
