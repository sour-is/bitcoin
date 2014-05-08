package address

import (
	"encoding/hex"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

var base58_plaintext string = "806A1B4E9EAD05B31AEA30FA22FFB6D07AA4EBFB6088832E1860F7B43A448DF288"
var base58_encoded string = "5Jd1w83AsSuNpNJMGYS1qzgzK6DVDb4ajEcxHbF7we56CfgQV34"
var base58_malformed string = "5Jd1w83AsSuNpNJMGYS1qzgzK6DVDb4ajEcxHbF7we56CfgQV33"

var base58bip38_encoded string = "6PfQoEzqbz3i2LpHibYnwAspwBwa3Nei1rU7UH9yzfutXT7tyUzV8aYAvG"
var base58bip38_plaintext string = "01430060accafae8e75b19b13afcd2043dcc33fa62b5c115c3fb82bfbcee5e2edcf75dabbc3b3d"

func TestBase58Encode(t *testing.T) {
	p, _ := hex.DecodeString(base58_plaintext)
	Convey(`Testing Base58 Encoding`, t, func() {
		b := ToBase58(p, 51)
		So(b, ShouldResemble, base58_encoded)
	})
}

func TestBase58Decode(t *testing.T) {
	p, _ := hex.DecodeString(base58_plaintext)
	Convey(`Testing Base58 Decoding`, t, func() {
		b, err := FromBase58(base58_encoded)
		So(err, ShouldBeNil)
		So(b, ShouldResemble, p)
	})
	Convey(`Testing Base58 Decoding Failure`, t, func() {
		_, err := FromBase58(base58_malformed)
		So(err, ShouldNotBeNil)
	})
}

func TestBase58DecodeBIP38(t *testing.T) {
	p, _ := hex.DecodeString(base58bip38_plaintext)
    Convey(`Test Base58 BIP38 Decode`, t,func(){
        b58, err := FromBase58(base58bip38_encoded)
        if err != nil {
            panic(err)
        }
        
        So(p, ShouldResemble, b58)
    })
}
