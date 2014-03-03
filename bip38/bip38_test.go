package bip38

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/sour-is/bitcoin/address"
	"testing"
)

type bip38_test struct {
	address string
	private string
	bip38   string
	phrase  string
}

var bip38_tests = []bip38_test{
	{"1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB",
		"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
		"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
		"TestingOneTwoThree"},
	{"1AvKt49sui9zfzGeo8EyL8ypvAhtR2KwbL",
		"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
		"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
		"Satoshi"},
	//	{"1FGAvMEfRzxqs8q5aLkUL3XRVApzWQneHw",
	//		"5JJJpSZn6aTPLuoQbzYoayZqYJ2Lvx29rs7AaUeirjLvXoFE7NX",
	//		"6PfVmVukmEMsz1HmgfqpJgapppXvqscx9NBYGhRv4tWQbvbSoyaisynW8u",
	//		"hello"},
	//	{"1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T",
	//		"5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS",
	//		"6PRKwcQ1g81NN5YMJka5EU8L3f1wZSPTZGHsjoszVqwJdihNCtqZiPggmu",
	//		"hello"},
}

func TestBIP38Encryption(t *testing.T) {
	Convey(`Encrypt Private Key`, t, func() {
		for _, i := range bip38_tests {
			p, err := address.ReadPrivateKey(i.private)
			if err != nil {
				panic(err)
			}

			So(p.Address(), ShouldResemble, i.address)

			b38 := Encrypt(p, i.phrase)
			So(b38, ShouldResemble, i.bip38)
		}
	})

	Convey(`Decrypt BIP38 Key`, t, func() {
		for _, i := range bip38_tests {
			b := address.FromBase58Raw(i.bip38)
			fmt.Printf("%s, %x\n", i.address, b)
			p, err := Decrypt(i.bip38, i.phrase)
			if err != nil {
				panic(err)
			}

			So(p.Address(), ShouldResemble, i.address)
			So(p.String(), ShouldResemble, i.private)
		}
	})
}
