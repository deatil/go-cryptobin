package gost

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Gosts(t *testing.T) {
    test_Gost(t, DESDerivedSbox, "DESDerivedSbox")
    test_Gost(t, TestSbox, "TestSbox")
    test_Gost(t, CryptoProSbox, "CryptoProSbox")
    test_Gost(t, SboxIdtc26gost28147paramZ, "SboxIdtc26gost28147paramZ")
}

func test_Gost(t *testing.T, sbox [][]byte, name string) {
    t.Run(name, func(t *testing.T) {
        random := rand.New(rand.NewSource(99))
        max := 5000

        var encrypted [8]byte
        var decrypted [8]byte

        for i := 0; i < max; i++ {
            key := make([]byte, 32)
            random.Read(key)
            value := make([]byte, 8)
            random.Read(value)

            cipher1, err := NewCipher(key, sbox)
            if err != nil {
                t.Fatal(err.Error())
            }

            cipher1.Encrypt(encrypted[:], value)

            cipher2, err := NewCipher(key, sbox)
            if err != nil {
                t.Fatal(err.Error())
            }

            cipher2.Decrypt(decrypted[:], encrypted[:])

            if !bytes.Equal(decrypted[:], value[:]) {
                t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
            }
        }
    })
}
