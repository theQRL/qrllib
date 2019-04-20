package golang

import (
	"testing"
	"github.com/theQRL/qrllib/goqrllib/goqrllib"
	"github.com/theQRL/qrllib/tests/golang/misc"
	"github.com/magiconair/properties/assert"
	)

func TestXMSSCreationHeight4(t *testing.T) {
	HEIGHT := uint8(4)

	seed := goqrllib.NewUcharVector(int64(48))
	xmss := goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128, goqrllib.SHA256_2X)

	expectedAddress := "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897"
	expectedPK := "010200c25188b585f731c128e2b457069e" +
		"afd1e3fa3961605af8c58a1aec4d82ac" +
		"316d3191da3442686282b3d5160f25cf" +
		"162a517fd2131f83fbf2698a58f9c46a" +
		"fc5d"

	if expectedPK != goqrllib.Bin2hstr(xmss.GetPK()) {
		t.Errorf("PK Mismatch\nExpected: %s\nFound: %s", expectedPK, goqrllib.Bin2hstr(xmss.GetPK()))
	}

	if expectedAddress != goqrllib.Bin2hstr(xmss.GetAddress()) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, goqrllib.Bin2hstr(xmss.GetAddress()))
	}

	tmpAddr := goqrllib.QRLHelperGetAddress(xmss.GetPK())
	if expectedAddress != goqrllib.Bin2hstr(tmpAddr) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, goqrllib.Bin2hstr(tmpAddr))
	}

	descr := goqrllib.QRLDescriptorFromExtendedPK(xmss.GetPK())
	if descr.GetHeight() != 4 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, descr.GetHeight())
	}

	if descr.GetHashFunction() != goqrllib.SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", goqrllib.SHAKE_128, descr.GetHashFunction())
	}
}

func TestXMSSCreationHeight6(t *testing.T) {
	HEIGHT := uint8(6)

	seed := goqrllib.NewUcharVector(int64(48))
	xmss := goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128, goqrllib.SHA256_2X)

	expectedAddress := "0103008b0e18dd0bac2c3fdc9a48e10fc466eef899ef074449d12ddf050317b2083527aee74bc3"
	expectedPK := "010300859060f15adc3825adeec85c7483" +
		          "d868e898bc5117d0cff04ab1343916d4" +
		          "07af3191da3442686282b3d5160f25cf" +
		          "162a517fd2131f83fbf2698a58f9c46a" +
		          "fc5d"

	if expectedPK != goqrllib.Bin2hstr(xmss.GetPK()) {
		t.Errorf("PK Mismatch\nExpected: %s\nFound: %s", expectedPK, goqrllib.Bin2hstr(xmss.GetPK()))
	}

	if expectedAddress != goqrllib.Bin2hstr(xmss.GetAddress()) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, goqrllib.Bin2hstr(xmss.GetAddress()))
	}

	tmpAddr := goqrllib.QRLHelperGetAddress(xmss.GetPK())
	if expectedAddress != goqrllib.Bin2hstr(tmpAddr) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, goqrllib.Bin2hstr(tmpAddr))
	}

	descr := goqrllib.QRLDescriptorFromExtendedPK(xmss.GetPK())
	if descr.GetHeight() != 6 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, descr.GetHeight())
	}

	if descr.GetHashFunction() != goqrllib.SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", goqrllib.SHAKE_128, descr.GetHashFunction())
	}
}

func TestXMSS(t *testing.T) {
	HEIGHT := uint8(4)

	seed := goqrllib.NewUcharVector(int64(48))
	xmss := goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128, goqrllib.SHA256_2X)

	if xmss == nil {
		t.Errorf("XMSS cannot be nil")
	}

	if xmss.GetHeight() != HEIGHT {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", HEIGHT, xmss.GetHeight())
	}

	message := misc.BytesToUCharVector(make([]byte, 32))
	for i := 0; i < 32; i++ {
		message.Set(i, byte (i))
	}

	signature := xmss.Sign(message)

	for i := 0; i < 1000; i++ {
		if !goqrllib.XmssBasicVerify(message, signature, xmss.GetPK()) {
			t.Errorf("Expected True")
		}
	}

	signature.Set(100, signature.Get(100) + 1)
	if goqrllib.XmssBasicVerify(message, signature, xmss.GetPK()) {
		t.Errorf("Expected False")
	}

	signature.Set(100, signature.Get(100) - 1)
	if !goqrllib.XmssBasicVerify(message, signature, xmss.GetPK()) {
		t.Errorf("Expected True")
	}

	message.Set(2, message.Get(2) + 1)
	if goqrllib.XmssBasicVerify(message, signature, xmss.GetPK()) {
		t.Errorf("Expected False")
	}

	message.Set(2, message.Get(2) - 1)
	if !goqrllib.XmssBasicVerify(message, signature, xmss.GetPK()) {
		t.Errorf("Expected True")
	}

}

func TestXMSSExceptionConstructor(t *testing.T) {
	HEIGHT := uint8(7)
	seed := goqrllib.NewUcharVector(int64(48))
	assert.Panic(
		t,
		func() {
			goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128)
		}, "For BDS traversal, H - K must be even, with H > K >= 2!")
}

func TestXMSSExceptionVerify(t *testing.T) {
	message := goqrllib.NewUcharVector(int64(48))
	signature := goqrllib.NewUcharVector(int64(2287))
	pk := goqrllib.NewUcharVector(int64(67))

	if goqrllib.XmssFastVerify(message, signature, pk) {
		t.Errorf("Expected False")
	}
}

func TestXMSSChangeIndexTooHigh(t *testing.T) {
	HEIGHT := uint8(4)
	seed := goqrllib.NewUcharVector(int64(48))
	xmss := goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128)

	assert.Panic(t, func() {xmss.SetIndex(20)}, "index too high")
}

func TestXMSSChangeIndexHigh(t *testing.T) {
	HEIGHT := uint8(4)
	seed := goqrllib.NewUcharVector(int64(48))
	xmss := goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128)

	assert.Panic(t, func() {xmss.SetIndex(16)}, "index too high")
}

func TestXMSSChangeIndexLimit(t *testing.T) {
	HEIGHT := uint8(4)
	seed := goqrllib.NewUcharVector(int64(48))
	xmss := goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128)

	xmss.SetIndex(15)
	if xmss.GetIndex() != 15 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 15, xmss.GetIndex())
	}
}

func TestXMSSChangeIndex(t *testing.T) {
	HEIGHT := uint8(4)
	seed := goqrllib.NewUcharVector(int64(48))
	xmss := goqrllib.NewXmssFast(seed, HEIGHT, goqrllib.SHAKE_128)

	xmss.SetIndex(0)
	if xmss.GetIndex() != 0 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 0, xmss.GetIndex())
	}
}
