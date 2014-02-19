package address

import (
	"fmt"
	"testing"
)

func TestGenerateKey(t *testing.T) {
    K, _  := NewPrivateKey(nil)

    fmt.Println(K)
    fmt.Println(K.PublicKey.Address())
    fmt.Println(K.PublicKey.Compress())
    
    ok := K.IsValid()
    if ok {
        t.Errorf("GENKEY")
    }
    
    S, err  := K.Sign( Hash256([]byte("asdf")) )
    if err != nil {
        t.Error(err)
    }
    
    fmt.Printf("%x\n", S)
}