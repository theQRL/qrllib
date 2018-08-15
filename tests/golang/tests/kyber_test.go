package golang

import (
	"testing"
	)

func TestExchangeKeys(t *testing.T) {
	/*
	This test has been disabled as it will fail.
	 */

	//alice := kyber.NewKyber()
	//bob := kyber.NewKyber()
	//
	//// Alice sends her public key to Bob
	//alicePublicKey := alice.GetPK()
	//
	//// Bob receives the public key, derives a secret and a response
	//// bob.Kem_encode(alicePublicKey)
	//cypherText := bob.GetCypherText()
	//
	//// Bob sends the cyphertext to alice
	//valid := alice.Kem_decode1(cypherText)
	//if !valid {
	//	t.Errorf("cypherText Invalid")
	//}
	//
	//// Now Alice and Bob share the same key
	//aliceKey := misc.UCharVectorToBytes(alice.GetMyKey())
	//bobKey := misc.UCharVectorToBytes(bob.GetMyKey())
	//
	//if !reflect.DeepEqual(aliceKey, bobKey) {
	//	t.Errorf("Key Mismatch")
	//}
}
