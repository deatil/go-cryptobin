package loki97

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/tool"
)

func Test_Key16(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher.Encrypt(encrypted[:], value)
        cipher.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key24(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 24)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher.Encrypt(encrypted[:], value)
        cipher.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key32(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher.Encrypt(encrypted[:], value)
        cipher.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Check(t *testing.T) {
    hexkey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    plain := "000102030405060708090a0b0c0d0e0f"

    hexcipher := "75080e359f10fe640144b35c57128dad"

    hexkeyByte, _ := hex.DecodeString(hexkey)
    plainByte, _ := hex.DecodeString(plain)

    cipher, err := NewCipher(hexkeyByte)
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [16]byte
    cipher.Encrypt(encrypted[:], plainByte)

    if hexcipher != fmt.Sprintf("%x", encrypted) {
        t.Error("Encrypt error")
    }
}

// 该测试数据为小端
// 包默认使用大端
// 如果加密数据为使用小端结果，请注意转换为大端
func Test_Check2(t *testing.T) {
    var key [32]byte

    for i := 0; i < 32; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    ciphertext := "8cb28c958024bae27a94c698f96f12a9"
    plaintext := "000102030405060708090a0b0c0d0e0f"

    // cipherBytes, _ := hex.DecodeString(ciphertext)
    plainBytes, _ := hex.DecodeString(plaintext)

    // 小端转大端
    for i := 0; i < len(key); i += 4 {
        k2 := tool.LE2BE_32(key[i:i+4])
        copy(key[i:i+4], k2[:])
    }

    for i := 0; i < len(plainBytes); i += 4 {
        p2 := tool.LE2BE_32(plainBytes[i:i+4])
        copy(plainBytes[i:i+4], p2[:])
    }

    cipher, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [16]byte
    cipher.Encrypt(encrypted[:], plainBytes)

    // 大端转小端
    for i := 0; i < len(encrypted); i += 4 {
        e2 := tool.BE2LE_32(encrypted[i:i+4])
        copy(encrypted[i:i+4], e2[:])
    }

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }
}
