package golang

import (
	"testing"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
	)

var (
	SHA2Input1 = "hello"
	SHA2ExpectedResult1 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	SHA2Input2 = "hello-qrl"
	SHA2ExpectedResult2 = "4ad6ad6c9ee6d2e52ebe4d635aa04052b7014e5e2e6b0de36da7648fac147703"
)

func CheckSHAResult(dataText string, expected string) bool {
	hexInBefore := goqrllib.Bin2hstr(goqrllib.Str2bin(dataText))
	dataOut := goqrllib.Sha2_256(goqrllib.Str2bin(dataText))

	hexIn := goqrllib.Bin2hstr(goqrllib.Str2bin(dataText))
	hexOut := goqrllib.Bin2hstr(dataOut)

	if hexInBefore != hexIn {
		return false
	}

	if expected != hexOut {
		return false
	}

	return true
}

func CheckSHANResult(dataText string, expected string, count int64) bool {
	hexInBefore := goqrllib.Bin2hstr(goqrllib.Str2bin(dataText))
	dataOut := goqrllib.Sha2_256_n(goqrllib.Str2bin(dataText), count)

	hexIn := goqrllib.Bin2hstr(goqrllib.Str2bin(dataText))
	hexOut := goqrllib.Bin2hstr(dataOut)

	if hexInBefore != hexIn {
		return false
	}

	if expected != hexOut {
		return false
	}

	return true
}

func TestCheckSHA2_256(t *testing.T) {
	if !CheckSHAResult(SHA2Input1, SHA2ExpectedResult1) {
		t.Errorf("Didnt match with expected value %s", SHA2ExpectedResult1)
	}
	if !CheckSHAResult(SHA2Input2, SHA2ExpectedResult2) {
		t.Errorf("Didnt match with expected value %s", SHA2ExpectedResult2)
	}
}

func TestCheckSHA_N_256(t *testing.T) {
	if !CheckSHANResult("This is a test X",
		"a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b", 1) {
		t.Errorf("Didnt match with expected value %s", SHA2Input1)
	}
	if !CheckSHANResult("This is a test X",
		"3be2d7e048d22de2c117465e5b4b819e764352680027c9790a53a7326d62a0fe", 16) {
		t.Errorf("Didnt match with expected value %s", SHA2Input2)
	}
}
