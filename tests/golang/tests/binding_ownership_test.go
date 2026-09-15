package golang

import (
	"testing"

	"github.com/theQRL/qrllib/goqrllib/dilithium"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
	"github.com/theQRL/qrllib/goqrllib/kyber"
)

func TestSecretOutputDeletionPaths(t *testing.T) {
	seed := goqrllib.NewUcharVector(int64(48))
	defer goqrllib.DeleteUcharVector(seed)
	xmss := goqrllib.NewXmssFast(seed, uint8(4), goqrllib.SHAKE_128)
	defer goqrllib.DeleteXmssFast(xmss)

	sk := xmss.GetSK()
	defer goqrllib.DeleteUcharVector(sk)
	seedCopy := xmss.GetSeed()
	defer goqrllib.DeleteUcharVector(seedCopy)
	extendedSeed := xmss.GetExtendedSeed()
	defer goqrllib.DeleteUcharVector(extendedSeed)
	skSeed := xmss.GetSKSeed()
	defer goqrllib.DeleteUcharVector(skSeed)
	skPRF := xmss.GetSKPRF()
	defer goqrllib.DeleteUcharVector(skPRF)

	if sk.Size() == 0 || seedCopy.Size() != 48 || extendedSeed.Size() != 51 ||
		skSeed.Size() != 32 || skPRF.Size() != 32 {
		t.Fatal("unexpected XMSS secret output size")
	}

	randomSeed := goqrllib.GetRandomSeed(48, "")
	defer goqrllib.DeleteUcharVector(randomSeed)
	hexSeed := goqrllib.Hstr2bin("00112233")
	defer goqrllib.DeleteUcharVector(hexSeed)
	mnemonicSeed := goqrllib.Mnemonic2bin("absorb absorb")
	defer goqrllib.DeleteUcharVector(mnemonicSeed)
	hashChain := goqrllib.GetHashChainSeed(randomSeed, 0, 2)
	defer goqrllib.DeleteX_string_list_list(hashChain)

	if randomSeed.Size() != 48 || hexSeed.Size() != 4 || mnemonicSeed.Size() != 3 ||
		hashChain.Size() != 2 || hashChain.Get(0).Size() != 32 {
		t.Fatal("unexpected global secret output size")
	}

	dilithiumKey := dilithium.NewDilithium()
	defer dilithium.DeleteDilithium(dilithiumKey)
	dilithiumSK := dilithiumKey.GetSK()
	defer dilithium.DeleteUcharVector(dilithiumSK)
	if dilithiumSK.Size() == 0 {
		t.Fatal("empty Dilithium secret key")
	}

	kyberKey := kyber.NewKyber()
	defer kyber.DeleteKyber(kyberKey)
	kyberSK := kyberKey.GetSK()
	defer kyber.DeleteUcharVector(kyberSK)
	peer := kyber.NewKyber()
	defer kyber.DeleteKyber(peer)
	peerPK := peer.GetPK()
	defer kyber.DeleteUcharVector(peerPK)
	if !kyberKey.Kem_encode(peerPK) {
		t.Fatal("Kyber encapsulation failed")
	}
	ciphertext := kyberKey.GetCypherText()
	defer kyber.DeleteUcharVector(ciphertext)
	if !peer.Kem_decode(ciphertext) {
		t.Fatal("Kyber decapsulation failed")
	}
	sharedKey := peer.GetMyKey()
	defer kyber.DeleteUcharVector(sharedKey)
	if kyberSK.Size() == 0 || sharedKey.Size() != 32 {
		t.Fatal("unexpected Kyber secret output size")
	}
}
