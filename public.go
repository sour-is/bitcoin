package bitcoin

import (
	"crypto/elliptic"
	"github.com/sour-is/koblitz/kelliptic"
	"math/big"
)

type PublicKey struct {
	X *big.Int
	Y *big.Int
}

func (p *PublicKey) Bytes() []byte {
	return []byte(p.String())
}

func (p *PublicKey) String() string {
	s256 := kelliptic.S256()

	if p.X == nil || p.Y == nil {
		return ""
	}

	b := elliptic.Marshal(s256, p.X, p.Y)

	hash := make([]byte, 21)
	copy(hash[1:], Rsha(b))

	return ToBase58(hash, 34)
}
