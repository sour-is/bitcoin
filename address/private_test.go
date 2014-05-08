package address

import (
	"encoding/hex"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	Convey(`Verify generated key`, t, func() {
		K, _ := NewPrivateKey(nil)
		So(K.IsValid(), ShouldBeTrue)
	})
}

func TestReadPrivateKey(t *testing.T) {
	PK_address := "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"
	PK_private := "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
	PK_bytes, _ := hex.DecodeString("C4BBCB1FBEC99D65BF59D85C8CB62EE2DB963F0FE106F483D9AFA73BD4E39A8A")

	Convey(`Verify Decoded Key`, t, func() {
		priv, err := ReadPrivateKey(PK_private)
		if err != nil {
			panic(err)
		}

		So(priv.Bytes(), ShouldResemble, PK_bytes)
		So(priv.Address(), ShouldResemble, PK_address)
	})
}

func TestECDSA(t *testing.T) {
	PK_private := "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
	priv, _ := ReadPrivateKey(PK_private)
    Convey(`Sign and Verify Hash`, t, func(){
        s, err := priv.Sign([]byte("Hello"))
        if err != nil {
            panic(err)
        }
        
        b := priv.Verify([]byte("Hello"), s)
        So(b, ShouldBeTrue)
    })
}