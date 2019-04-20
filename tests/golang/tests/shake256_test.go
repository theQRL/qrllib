package golang

import (
	"testing"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
	)

var (
	shake256Input1 = "hello"
	shake256ExpectedResult1 = "1234075ae4a1e77316cf2d8000974581a343b9ebbc" +
							  "a7e3d1db83394c30f221626f594e4f0de63902349a" +
							  "5ea5781213215813919f92a4d86d127466e3d07e8be3"
	shake256Input2 = "hello-1234"
	shake256ExpectedResult2 = "4a01ca14fd8468f2d2e3a0b3d7597731ad15501675" +
		                      "3677807ed735b022a9944e61586a6378fc6ffe49e9" +
		                      "e0e456f8e2bbfaa41330c5ae7005a2d24ac8f0597e60"
)

func CheckShake256Result(dataText string, expected string) bool {
	hexInBefore := goqrllib.Bin2hstr(goqrllib.Str2bin(dataText))
	dataOut := goqrllib.Shake256(64, goqrllib.Str2bin(dataText))

	hexIn := goqrllib.Bin2hstr(goqrllib.Str2bin(dataText))
	hexOut := goqrllib.Bin2hstr(dataOut)

	if hexIn != hexInBefore {
		return false
	}

	if hexOut != expected {
		return false
	}

	return true
}

func TestCheckShake256(t *testing.T) {
	if !CheckShake256Result(shake256Input1, shake256ExpectedResult1) {
		t.Errorf("Didnt match with expected value %s", shake256ExpectedResult1)
	}

	if !CheckShake256Result(shake256Input2, shake256ExpectedResult2) {
		t.Errorf("Didnt match with expected value %s", shake256ExpectedResult2)
	}
}
