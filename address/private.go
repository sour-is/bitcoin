package address

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/sour-is/koblitz/kelliptic"
	"io"
	"math/big"
)

type PrivateKey struct {
	Data [32]byte
}

func NewPrivateKey(seed io.Reader) (priv *PrivateKey, pub *PublicKey) {
	if seed == nil {
		seed = rand.Reader
	}
	s256 := kelliptic.S256()

	pub = new(PublicKey)
	priv = new(PrivateKey)

	d, x, y, _ := elliptic.GenerateKey(s256, seed)
	copy(priv.Data[:], d[:])
	pub.X = x
	pub.Y = y

	return
}

func ReadPrivateKey(s string) (priv *PrivateKey, pub *PublicKey, err error) {

	pub = new(PublicKey)
	priv = new(PrivateKey)

	if len(s) == 64 { // If 32 bytes assume it is hex encoded.
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, nil, err
		}
		copy(priv.Data[:], b[:])
	} else if len(s) == 51 && s[0] == '5' {
		b, err := FromBase58(s)
		if err != nil {
			return nil, nil, err
		}
		copy(priv.Data[:], b[1:])
	} else {
		return nil, nil, errors.New("Invalid PrivateKey: Format not Recognized. (" + s + ")")
	}

	if priv.IsValid() {
		return nil, nil, errors.New("Invalid PrivateKey: Out of Curve")
	}

	pub = priv.PublicKey()

	return
}

func (p *PrivateKey) PublicKey() (pub *PublicKey) {
	s256 := kelliptic.S256()

	pub = new(PublicKey)
	pub.X, pub.Y = s256.ScalarBaseMult(p.Data[:])

	return
}

func (p *PrivateKey) IsValid() bool {
	max, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	min := big.NewInt(1)
	cmp := new(big.Int).SetBytes(p.Data[:])

	if cmp.Cmp(min) > 0 {
		return false
	}

	if cmp.Cmp(max) < 0 {
		return false
	}

	return true
}

func (p *PrivateKey) Bytes() []byte {
	addr := make([]byte, 32)
	copy(addr, p.Data[:])

	return addr
}

func (p *PrivateKey) String() string {
	addr := make([]byte, 33)

	addr[0] = 0x80
	copy(addr[1:33], p.Data[:])

	return ToBase58(addr, 51)
}

func (p *PrivateKey) Address() string {
	return p.PublicKey().Address()
}

func (p *PrivateKey) AddressBytes() []byte {
	return p.PublicKey().AddressBytes()
}
