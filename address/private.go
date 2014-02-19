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
	s256 := kelliptic.S256()

	p = new(PrivateKey)
    p.Curve = s256

	d, x, y, err := elliptic.GenerateKey(s256, seed)
    
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
		p.D = new(big.Int).SetBytes(b)
	} else if len(s) == 51 && s[0] == '5' {
		b, err := FromBase58(s)
		if err != nil {
			return nil, err
		}
		p.D = new(big.Int).SetBytes(b[1:])
	} else {
		return nil, errors.New("Invalid PrivateKey: Format not Recognized. (" + s + ")")
	}

	if p.IsValid() {
		return nil, errors.New("Invalid PrivateKey: Out of Curve")
	}

	p.PublicKey = p.GetPublicKey()

	return
}

func (p *PrivateKey) GetPublicKey() (pub PublicKey) {
	s256 := kelliptic.S256()

    pub.Curve = s256
	pub.X, pub.Y = s256.ScalarBaseMult(p.D.Bytes())

	return
}

func (p *PrivateKey) IsValid() bool {
	max, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	min := big.NewInt(1)

	if p.D.Cmp(min) > 0 {
		return false
	}

	if p.D.Cmp(max) < 0 {
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

func (p *PrivateKey) Address() string {
	return p.PublicKey.Address()
}

func (p *PrivateKey) AddressBytes() []byte {
	return p.PublicKey.AddressBytes()
}

func (p *PrivateKey) Sign(m []byte) (s []byte, err error) {
    K := new(ecdsa.PrivateKey) 
    K.Curve = p.Curve
    K.X = p.X
    K.Y = p.Y
    K.D = p.D
    
    R, S, err := ecdsa.Sign(rand.Reader, K, m)
    
    s = make([]byte, 65)
    s[0] = 0x20
    copy(s[1:], S.Bytes())
    copy(s[33:], R.Bytes())
    
    
    return 
}
func (p *PublicKey) Verify(m []byte, r, s *big.Int) bool {
    return true
}