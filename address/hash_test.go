package address

import (
	"encoding/hex"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

var hash_text string = "Test string for hash."
var hash_h256 string = "6bec70ede8f279cfff321477c48ce14194084ab2756978ed72afa93f6a8df1cc"
var hash_h160 string = "d29c6773ea54787a9b5b256b3e1092a4a6452f30"

func TestHash256(t *testing.T) {
	h, _ := hex.DecodeString(hash_h256)
	Convey(`Testing Double SHA 256 Hash`, t, func() {
		v := Hash256([]byte(hash_text))
		So(v, ShouldResemble, h)
	})
}

func TestHash160(t *testing.T) {
	h, _ := hex.DecodeString(hash_h160)
	Convey(`Testing SHA 256 / Ripe 160 Hash`, t, func() {
		v := Hash160([]byte(hash_text))
		So(v, ShouldResemble, h)
	})
}
