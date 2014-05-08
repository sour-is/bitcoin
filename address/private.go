package address

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/sour-is/koblitz/kelliptic"
	"io"
	"math/big"
)

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func NewPrivateKey(seed io.Reader) (p *PrivateKey, err error) {
	if seed == nil {
		seed = rand.Reader
	}

	p = new(PrivateKey)
	p.Curve = kelliptic.S256()

	d, x, y, err := elliptic.GenerateKey(p.Curve, seed)
	if err != nil {
		return nil, err
	}

	p.D = new(big.Int).SetBytes(d)
	p.X = x
	p.Y = y

	return
}

func ReadPrivateKey(s string) (p *PrivateKey, err error) {

	p = new(PrivateKey)

	if len(s) == 64 { // If 32 bytes assume it is hex encoded.
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		p.SetBytes(b)
	} else if len(s) == 51 && s[0] == '5' {
		b, err := FromBase58(s)
		if err != nil {
			return nil, err
		}
		p.SetBytes(b[1:])
	} else {
		return nil, errors.New("Invalid PrivateKey: Format not Recognized. (" + s + ")")
	}

	if !p.IsValid() {
		return nil, errors.New("Invalid PrivateKey: Out of Curve")
	}

	return
}

func (p *PrivateKey) SetBytes(b []byte) *PrivateKey {
	p.Curve = kelliptic.S256()
	p.D = new(big.Int).SetBytes(b)
	p.X, p.Y = p.ScalarBaseMult(b)

	return p
}

func (p *PrivateKey) IsValid() bool {
	min := big.NewInt(1)

	if min.Cmp(p.D) > 0 {
		return false
	}

	if p.N.Cmp(p.D) < 0 { // The order n of G for the Curve
		return false
	}

	return true
}

func (p *PrivateKey) Bytes() []byte {
	return p.D.Bytes()
}

func (p *PrivateKey) String() string {
	addr := make([]byte, 33)

	addr[0] = 0x80
	copy(addr[1:33], p.D.Bytes())

	return ToBase58(addr, 51)
}

func (p *PrivateKey) Sign(m []byte) (s []byte, err error) {
	K := new(ecdsa.PrivateKey)
	K.Curve, K.X, K.Y, K.D = p.Curve, p.X, p.Y, p.D

	R, S, err := ecdsa.Sign(rand.Reader, K, m)

	s = make([]byte, 65)
	s[0] = 0x20
	copy(s[1:], S.Bytes())
	copy(s[33:], R.Bytes())

	return
}

func (p *PublicKey) Verify(m, s []byte) bool {
    P := new(ecdsa.PublicKey)
    P.Curve, P.X, P.Y = p.Curve, p.X, p.Y
    
    R := new(big.Int).SetBytes(s[33:])
    S := new(big.Int).SetBytes(s[1:33])
    
	return ecdsa.Verify(P, m, R, S)
}
