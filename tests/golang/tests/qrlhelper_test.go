package golang

import (
	"testing"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
	"github.com/theQRL/qrllib/tests/golang/misc"
	)

func TestEmpty(t *testing.T) {
	if goqrllib.QRLHelperAddressIsValid(misc.BytesToUCharVector([]byte(""))) {
		t.Errorf("An Invalid Address is considered as valid")
	}
}