package bitcoin

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"fmt"
)

type BIP38Key struct {
	Flag byte
	Hash [4]byte
	Data [32]byte
}

func BIP38LoadString(b58 string) (bip38 *BIP38Key, err error) {
	b, err := FromBase58(b58)
	if err != nil {
		return nil, err
	}

	bip38 = new(BIP38Key)

	bip38.Flag = b[3]
	copy(bip38.Hash[:], b[3:7])
	copy(bip38.Data[:], b[7:])

	return
}

func (p PrivateKey) BIP38Encrypt(passphrase string) (bip *BIP38Key) {
	bip = new(BIP38Key)

	address := []byte(p.PublicKey().String())

	ah := Dsha(address)[:4]
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)

	bip.Flag = byte(0xC0)
	copy(bip.Hash[:], ah)
	copy(bip.Data[:], encrypt(p.Data[:], dh[:32], dh[32:]))

	return
}

func (bip BIP38Key) BIP38Decrypt(passphrase string) (priv *PrivateKey, err error) {
	dh, _ := scrypt.Key([]byte(passphrase), bip.Hash[:], 16384, 8, 8, 64)
	priv = new(PrivateKey)

	fmt.Printf("ah:%x - dh:%x\n", bip.Hash[:], dh)

	p := decrypt(bip.Data[:], dh[:32], dh[32:])
	copy(priv.Data[:], p)

	return
}

func (bip BIP38Key) String() string {
	return ToBase58(bip.Bytes(), 58)
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
