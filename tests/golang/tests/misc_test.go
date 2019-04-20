package golang

import (
	"testing"
	"reflect"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
	"github.com/theQRL/qrllib/tests/golang/misc"
	"github.com/magiconair/properties/assert"
	)

func TestDataToHex1(t *testing.T) {
	hexString := goqrllib.Bin2hstr__SWIG_2("\x00\x11\x22\x33", 0)
	if hexString != "00112233" {
		t.Errorf("hexString mismatch\nExpected: %s\nFound: %s", "00112233", hexString)
	}
}

func TestDataToHex2(t *testing.T) {
	hexString := goqrllib.Bin2hstr__SWIG_2("test", 0)
	if hexString != "74657374" {
		t.Errorf("hexString mismatch\nExpected: %s\nFound: %s", "74657374", hexString)
	}
}

func TestMnemonicWordsOdd1(t *testing.T) {
	assert.Panic(t, func() {goqrllib.Mnemonic2bin("absorb")}, "word count = 1 must be even")
}

func TestMnemonicWordsOdd2(t *testing.T) {
	assert.Panic(t, func() {goqrllib.Mnemonic2bin("absorb bunny bunny")},"word count = 3 must be even")
}

func TestMnemonic1(t *testing.T) {
	found := misc.UCharVectorToBytes(goqrllib.Mnemonic2bin("aback absorb"))
	expected := misc.UCharVectorToBytes(misc.BytesToUCharVector([]byte {0, 0, 16}))

	if !reflect.DeepEqual(found, expected) {
		t.Errorf("Mnemonic mismatch\nExpected: %s\nFound: %s", expected, found)
	}
}

func TestMnemonic2(t *testing.T) {
	found := misc.UCharVectorToBytes(goqrllib.Mnemonic2bin("absorb absorb"))
	expected := misc.UCharVectorToBytes(misc.BytesToUCharVector([]byte {1, 0, 16}))

	if !reflect.DeepEqual(found, expected) {
		t.Errorf("Mnemonic mismatch\nExpected: %s\nFound: %s", expected, found)
	}
}

func TestMnemonic3(t *testing.T) {
	mnemonic := "law bruise screen lunar than loft but franc strike asleep dwarf tavern dragon alarm " +
			    "snack queen meadow thing far cotton add emblem strive probe zurich edge peer alight " +
		        "libel won corn medal"
	found := misc.UCharVectorToBytes(goqrllib.Mnemonic2bin(mnemonic))
	expected := misc.UCharVectorToBytes(goqrllib.Hstr2bin(
		"7ad1e6c1083de2081221056dd8b0c142cdfa3fd053cd4ae288ee324cd30e027462d8eaaffff445a1105b7e4fc1302894"))

	if !reflect.DeepEqual(found, expected) {
		t.Errorf("Mnemonic mismatch\nExpected: %s\nFound: %s", expected, found)
	}
}

func TestMnemonic4(t *testing.T) {
	bin := goqrllib.Mnemonic2bin("absorb absorb")
	found := goqrllib.Bin2mnemonic(bin)
	expected := "absorb absorb"

	if found != expected {
		t.Errorf("Mnemonic mismatch\nExpected: %s\nFound: %s", expected, found)
	}
}

func TestException(t *testing.T) {
	assert.Panic(t, func() {
		goqrllib.Hstr2bin("Z")
	}, "hex string is expected to have an even number of characters")

	assert.Panic(t, func() {goqrllib.Hstr2bin("Z0")}, "invalid hex digits in the string")
}
