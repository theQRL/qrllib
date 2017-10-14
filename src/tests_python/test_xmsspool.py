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
        self.assertEqual( "2cdddec48985cc9acd9d970781782a1c5f1000ee464370b79a8639dc669defb803eb90b52a39a2be669053476fa1bb3eb8d9514c432eb9bd1e4a78b36d271d7e",
                          pyqrllib.bin2hstr(xmss.getPK()))

        xmss = pool.getNextTree()
        self.assertEqual( "e76e8a65bd7df657e91b95a9895baebbca7f003e3ab8ae6e7bcf6edc0d48f212551a7d78a5df848aa9808f39e669817362e0870178c1a70c1e835b6daa0b3d91",
                          pyqrllib.bin2hstr(xmss.getPK()))

        xmss = pool.getNextTree()
        self.assertEqual( "87eb6f611bd88cf08f7948995216661e01fce87f9dcff14d58858e8770422c69691d6ce737e816c44bc21e8e7e422e8068af1d8bfb89a05db98e822178352d63",
                          pyqrllib.bin2hstr(xmss.getPK()))

        xmss = pool.getNextTree()
        self.assertEqual( "e3d66e891f02bff7dcb2d87fe7126e549e0e993b6a459992fc5fcc4b752eeb4ab2428e3e0280b7da7c82db6c135ab615cddd08412246580eee32e9c692eaa318",
                          pyqrllib.bin2hstr(xmss.getPK()))
