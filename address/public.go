package address

import (
	"crypto/elliptic"
	"github.com/sour-is/bitcoin/op"
	"github.com/sour-is/koblitz/kelliptic"
	"math/big"
)

type PublicKey struct {
	X *big.Int
	Y *big.Int
}

func (p *PublicKey) String() string {
	return p.Address()
}

func (p *PublicKey) Bytes() []byte {
	if p.X == nil || p.Y == nil {
		return []byte{}
	}

	s256 := kelliptic.S256()
	return elliptic.Marshal(s256, p.X, p.Y)
}

func (p *PublicKey) Address() string {
	b := p.Bytes()

	hash := make([]byte, 21)
	copy(hash[1:], op.Hash160(b))

	return ToBase58(hash, 34)
}
func (p *PublicKey) AddressBytes() []byte {
	return []byte(p.String())
}
