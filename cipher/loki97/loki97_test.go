package loki97

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
    "encoding/base64"
)

func testCipher(t *testing.T) {
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

func testCipher2(t *testing.T) {
    var encrypted [16]byte
    var decrypted [16]byte

    key := []byte("asdfdcvf8kioljik")
    value := []byte("asdfasdfcvbncvbn")

    cipher, err := NewCipher(key)
    if err != nil {
        t.Fatal(err.Error())
    }

    cipher.Encrypt(encrypted[:], value)
    cipher.Decrypt(decrypted[:], encrypted[:])

    if !bytes.Equal(decrypted[:], value[:]) {
        t.Errorf("encryption/decryption failed: %s != %s\n", decrypted, value)
    }

}

func testCheck(t *testing.T) {
    var encrypted [16]byte

    key := []byte("1234567812345678")
    value := []byte("1234567812345678")

    // data := "m6JMvqjGEw89in5cpg0+BQ=="

    cipher, err := NewCipher(key)
    if err != nil {
        t.Fatal(err.Error())
    }

    cipher.Encrypt(encrypted[:], value)

    res := base64.StdEncoding.EncodeToString(encrypted[:])
    t.Error(res)
}

func TestCheck3(t *testing.T) {
    var encrypted [16]byte

    // hexkey := "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    // hexcipher := "75080e359f10fe640144b35c57128dad"

    key := []byte{
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1F,
    }

    plain := []byte{
        byte(0), byte(1), byte(2), byte(3),
        byte(4), byte(5), byte(6), byte(7),
        byte(8), byte(9), byte(10), byte(11),
        byte(12), byte(13), byte(14), byte(15),
    }

    cipher, err := NewCipher(key)
    if err != nil {
        t.Fatal(err.Error())
    }

    cipher.Encrypt(encrypted[:], plain)

    res := hex.EncodeToString(encrypted[:])
    t.Error(res)
}
