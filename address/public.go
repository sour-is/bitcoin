package address

import (
	"crypto/elliptic"
	"encoding/hex"
	"github.com/sour-is/koblitz/kelliptic"
	"math/big"
)

type PublicKey struct {
	*kelliptic.Curve
	X, Y *big.Int
}

func (p *PublicKey) String() string {
	return hex.EncodeToString(p.Bytes())
}

func (p *PublicKey) Bytes() []byte {
	if p.X == nil || p.Y == nil {
		return []byte{}
	}

	return elliptic.Marshal(p.Curve, p.X, p.Y)
}

func (p *PublicKey) Address() string {
	b := p.Bytes()

	hash := make([]byte, 21)
	copy(hash[1:], Hash160(b))

	return ToBase58(hash, 34)
}

func (p *PublicKey) AddressBytes() []byte {
	return []byte(p.Address())
}

func (p *PublicKey) Compress() string {

	hash := make([]byte, 34)
	copy(hash[1:], p.Curve.CompressPoint(p.X, p.Y))

	return ToBase58(hash, 60)
}

func (p *PublicKey) CompressBytes() []byte {
	return p.Curve.CompressPoint(p.X, p.Y)
}

