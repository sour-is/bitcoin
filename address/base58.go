package address

import (
	"bytes"
	"errors"
	"math/big"
)

// Adds a checksum to bytes before converting to base58
func ToBase58(b []byte, l int) string {
	check := make([]byte, len(b)+4)
	copy(check, b)
	copy(check[len(b):], Hash256(b))
	return ToBase58Raw(check, l)
}

// Validates checksum and strips it from result
func FromBase58(s string) ([]byte, error) {
	b := FromBase58Raw(s)
	l := len(b) - 4
	if bytes.Compare(b[l:], Hash256(b[:l])[:4]) != 0 {
		return nil, errors.New("FromBase58: Invalid Checksum")
	}
	return b[:l], nil
}

//encodes bytes into base58 string
func ToBase58Raw(val []byte, len int) string {
	base58alph := []rune("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

	zero := big.NewInt(0)
	base := big.NewInt(58)
	mod := big.NewInt(0)
	store := big.NewInt(0)

	for _, v := range val {
		store.Lsh(store, 8)
		store.Add(store, big.NewInt(int64(v)))
	}

	out := make([]rune, len)
	pos := len - 1

	for store.Cmp(zero) > 0 && pos >= 0 {
		store.DivMod(store, base, mod)
		i := mod.Int64()
		out[pos] = base58alph[i]
		pos--
	}
	if pos >= 0 {
		out[pos] = '1'
	}

	return string(out)
}

//encodes base58 string into bytes
func FromBase58Raw(src string) (dst []byte) {
	base58alph := map[string]int{
		"1": 0, "2": 1, "3": 2, "4": 3, "5": 4, "6": 5, "7": 6, "8": 7, "9": 8, "A": 9,
		"B": 10, "C": 11, "D": 12, "E": 13, "F": 14, "G": 15, "H": 16, "J": 17, "K": 18, "L": 19,
		"M": 20, "N": 21, "P": 22, "Q": 23, "R": 24, "S": 25, "T": 26, "U": 27, "V": 28, "W": 29,
		"X": 30, "Y": 31, "Z": 32, "a": 33, "b": 34, "c": 35, "d": 36, "e": 37, "f": 38, "g": 39,
		"h": 40, "i": 41, "j": 42, "k": 43, "m": 44, "n": 45, "o": 46, "p": 47, "q": 48, "r": 49,
		"s": 50, "t": 51, "u": 52, "v": 53, "w": 54, "x": 55, "y": 56, "z": 57}

	answer := new(big.Int)
	base := big.NewInt(58)

	for _, v := range src {
		answer.Mul(answer, base)                                     //multiply current value by 58
		answer.Add(answer, big.NewInt(int64(base58alph[string(v)]))) //add value of the current letter
	}

	return answer.Bytes()
}
