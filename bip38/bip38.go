package bip38

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"github.com/sour-is/bitcoin/address"
	"github.com/sour-is/koblitz/kelliptic"
)

type BIP38Key struct {
	Flag byte
	Hash [4]byte
	Data [32]byte
}

func Encrypt(p *address.PrivateKey, passphrase string) string {
	bip38 := new(BIP38Key)

	fmt.Printf("ADDR: %x %x\n", p.Address(), p.AddressBytes())

	ah := address.Hash256(p.AddressBytes())[:4]
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)

	fmt.Printf("%x %x ", p.Bytes(), ah)

	bip38.Flag = byte(0xC0)
	copy(bip38.Hash[:], ah)
	copy(bip38.Data[:], encrypt(p.Bytes(), dh[:32], dh[32:]))

	fmt.Printf("%x\n", bip38.Data)

	return bip38.String()
}

func Decrypt(b38 string, passphrase string) (priv *address.PrivateKey, err error) {
	b, err := address.FromBase58(b38)
	if err != nil {
		return nil, err
	}
	bip38 := new(BIP38Key)

	bip38.Flag = b[2]
	copy(bip38.Hash[:], b[3:7])
	copy(bip38.Data[:], b[7:])

	dh, _ := scrypt.Key([]byte(passphrase), bip38.Hash[:], 16384, 8, 8, 64)
	priv = new(address.PrivateKey)

	p := decrypt(bip38.Data[:], dh[:32], dh[32:])
	priv.SetBytes(p)

	return
}

func (bip BIP38Key) String() string {
	return address.ToBase58(bip.Bytes(), 58)
}

func (bip BIP38Key) Bytes() []byte {
	dst := make([]byte, 39)

	dst[0] = byte(0x01)
	dst[1] = byte(0x42)
	dst[2] = bip.Flag

	copy(dst[3:], bip.Hash[:])
	copy(dst[7:], bip.Data[:])

	return dst
}

func encrypt(pk, dh1, dh2 []byte) (dst []byte) {
	c, _ := aes.NewCipher(dh2)

	for i, _ := range dh1 {
		dh1[i] ^= pk[i]
	}

	dst = make([]byte, 48)
	c.Encrypt(dst, dh1[:16])
	c.Encrypt(dst[16:], dh1[16:])
	dst = dst[:32]

	return
}

func decrypt(src, dh1, dh2 []byte) (dst []byte) {
	c, _ := aes.NewCipher(dh2)

	dst = make([]byte, 48)
	c.Decrypt(dst, src[:16])
	c.Decrypt(dst[16:], src[16:])
	dst = dst[:32]

	for i := range dst {
		dst[i] ^= dh1[i]
	}

	return
}

// Intermediate Code Generation
func NewIntermediate(p string) (string, error) {
	in := make([]byte, 49)

	copy(in, []byte{0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53})

	rand.Read(in[8:16])

	sc, _ := scrypt.Key([]byte(p), in[8:16], 16384, 8, 8, 32)

	s256 := kelliptic.S256()
	x, y := s256.ScalarBaseMult(sc)

	cp := s256.CompressPoint(x, y)
	copy(in[16:], cp)

	return address.ToBase58(in, 72), nil
}

/*
func NewIntermediateLot(p string, lot, seq int) (string, error) {
	if lot < 0 || lot > 4096 {
		return "", errors.New("BIP38: lot out of range")
	}
	if seq < 0 || seq > 1048575 {
		return "", errors.New("BIP38: sequence out of range")
	}

	lotseq := make([]byte, 8)
	n := binary.PutVarint(lotseq, int64(lot*4096+seq))

	salt := make([]byte, 16)
	rand.Read(salt[8:12])
	copy(salt[12-n:16], lotseq[:4])

	sc, _ := scrypt.Key([]byte(p), salt[8:16], 16384, 8, 8, 32)
	copy(salt[:8], sc)

	//	copy(in, []byte{0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53})

	return "", nil
}

func DecodeIntermediate(p string) error {
	in, err := FromBase58(p)
	if err != nil {
		return err
	}

	s256 := kelliptic.S256()
	x, y, err := s256.DecompressPoint(in[16:])
	if err != nil {
		return err
	}

	fmt.Printf("End   X: %x Y: %x\n", x, y)

	return nil
}
*/
