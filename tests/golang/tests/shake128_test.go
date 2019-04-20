package golang

import (
	"testing"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
	)

var (
	shake128Input1 = "hello"
	shake128ExpectedResult1 = "8eb4b6a932f280335ee1a279f8c208a349e7bc65daf831d3021c213825292463"
	shake128Input2 = "hello-qrl"
	shake128ExpectedResult2 = "50028af4e91b430a1ec24924edc707b0d24ab01be44ea5f5c5c111087e9aadcb"
)

func CheckShake128Result(dataText string, expected string) bool {
	hexInBefore := goqrllib.Bin2hstr(goqrllib.Str2bin(dataText))
	dataOut := goqrllib.Shake128(32, goqrllib.Str2bin(dataText))

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

func TestCheckShake128(t *testing.T) {
	if !CheckShake128Result(shake128Input1, shake128ExpectedResult1) {
		t.Errorf("Didnt match with expected value %s", shake128ExpectedResult1)
	}

	if !CheckShake128Result(shake128Input2, shake128ExpectedResult2) {
		t.Errorf("Didnt match with expected value %s", shake128ExpectedResult2)
	}
}

