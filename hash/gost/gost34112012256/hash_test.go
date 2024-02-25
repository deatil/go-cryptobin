package gost34112012256

import (
    "fmt"
    "hash"
    "testing"
    "crypto/hmac"
    "encoding/hex"
    "encoding/binary"
)

func TestHashInterface(t *testing.T) {
    h := New()
    var _ hash.Hash = h
}

func TestHashed(t *testing.T) {
    h := New()
    m := make([]byte, BlockSize)
    for i := 0; i < BlockSize; i++ {
        m[i] = byte(i)
    }

    h.Write(m)
    hashed := h.Sum(nil)

    if len(hashed) == 0 {
        t.Error("Hash error")
    }
}

func Test_ESPTree(t *testing.T) {
    data := NewESPTree([]byte("rgtf5yds")).Derive([]byte("olkpj"))

    if len(data) == 0 {
        t.Error("ESPTree data error")
    }
}

func Test_TLSTree(t *testing.T) {
    num := binary.BigEndian.Uint64([]byte{0xFE, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00})

    data := NewTLSTree(TLSKuznyechikCTROMAC, []byte("rgtf5yds")).Derive(num)

    if len(data) == 0 {
        t.Error("TLSTree data error")
    }
}

func Test_Check(t *testing.T) {
    in := []byte("nonce-asdfg123123123")
    check := "f24a63bbb863ba538ad956ababb0c4a651136a4d81c878a818bad28c9094d8e1"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}

func Test_Check_2(t *testing.T) {
    in, _ := hex.DecodeString("0126bdb87800af214341456563780100")
    key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    check := "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"

    mac := hmac.New(New, key)
    mac.Write(in)

    out := mac.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check 2 error. got %x, want %s", out, check)
    }
}
