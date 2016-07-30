package address

import (
	"golang.org/x/crypto/ripemd160"
	"crypto/sha256"
)

func Hash256(in []byte) []byte {
	s1 := sha256.New()
	s2 := sha256.New()

	s1.Write(in)
	s2.Write(s1.Sum(nil))

	return s2.Sum(nil)
}

func Hash160(in []byte) []byte {
	s := sha256.New()
	r := ripemd160.New()

	s.Write(in)
	r.Write(s.Sum(nil))

	return r.Sum(nil)
}
