package address

import (
	"crypto/elliptic"
	"fmt"
	"github.com/sour-is/koblitz/kelliptic"
	"github.com/sour-is/bitcoin/op"    
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
	fmt.Printf("pub: %x\n", b)
	hash := make([]byte, 21)
	copy(hash[1:], op.Hash160(b))

	return ToBase58(hash, 34)
}
