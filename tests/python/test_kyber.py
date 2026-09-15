# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from __future__ import print_function

import unittest
from unittest import TestCase

from pyqrllib.kyber import Kyber
from pyqrllib.pyqrllib import ucharVector


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

    def test_fixed_size_boundaries_and_implicit_rejection(self):
        recipient = Kyber()
        sender = Kyber()
        peer_pk = recipient.getPK()

        for size in (0, 1087, 1089):
            self.assertTrue(sender.kem_encode(peer_pk))
            self.assertFalse(sender.kem_encode(ucharVector(size, 0)))
            self.assertEqual(0, len(sender.getMyKey()))
            self.assertEqual(0, len(sender.getCypherText()))

        self.assertTrue(sender.kem_encode(peer_pk))
        ciphertext = sender.getCypherText()
        self.assertEqual(1152, len(ciphertext))

        for size in (0, 1151, 1153):
            self.assertTrue(recipient.kem_decode(ciphertext))
            self.assertFalse(recipient.kem_decode(ucharVector(size, 0)))
            self.assertEqual(0, len(recipient.getMyKey()))

        self.assertTrue(recipient.kem_decode(ciphertext))
        accepted_key = bytes(recipient.getMyKey())
        rejected_ciphertext = ucharVector([value for value in ciphertext])
        rejected_ciphertext[0] ^= 1
        self.assertFalse(recipient.kem_decode(rejected_ciphertext))
        rejection_key = bytes(recipient.getMyKey())
        self.assertEqual(32, len(rejection_key))
        self.assertNotEqual(accepted_key, rejection_key)


if __name__ == '__main__':
    unittest.main()
