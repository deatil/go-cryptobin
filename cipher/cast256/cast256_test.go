package cast256

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Key256(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key224(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 28)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key192(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 24)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key160(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 20)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key128(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Check(t *testing.T) {
    var key [32]byte

    for i := 0; i < 32; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    plaintext := "000102030405060708090a0b0c0d0e0f"
    ciphertext := "47cc8266c2221328a7398f2655551d6a"

    cipherBytes, _ := hex.DecodeString(ciphertext)
    plainBytes, _ := hex.DecodeString(plaintext)

    cipher, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted []byte = make([]byte, len(plainBytes))
    cipher.Encrypt(encrypted, plainBytes)

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }

    // ==========

    cipher2, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted []byte = make([]byte, len(cipherBytes))
    cipher2.Decrypt(decrypted, cipherBytes)

    if plaintext != fmt.Sprintf("%x", decrypted) {
        t.Errorf("Decrypt error: act=%x, old=%s\n", decrypted, plaintext)
    }
}

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    keylen int32
    pt []byte
    ct []byte
    key []byte
}

func Test_Check_List(t *testing.T) {
   tests := []testData{
        {
           32,
           fromHex("000000000000000000000000bdf4e311"),
           fromHex("fa5874ab5aba5c0ba20aa82124c8f5a5"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },
        {
           32,
           fromHex("000000000000000000000000cf05f422"),
           fromHex("f61772310e2160770eb7e7e92469ff32"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },
        {
           32,
           fromHex("000000000000000000000000f0271543"),
           fromHex("ad9493d3f4891ebba47aa9605edb432e"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },

        {
           24,
           fromHex("000000000000000000000000de255aff"),
           fromHex("2bc1929f301347a99d3f3e45ad3401e8"),
           fromHex("2342bb9efa38542cbed0ac83940ac298bac77a7717942863"),
        },
        {
           24,
           fromHex("000000000000000000000000e2295f03"),
           fromHex("bfeaf5bc2b1bcbbe32a93b9900365923"),
           fromHex("2342bb9efa38542cbed0ac83940ac298bac77a7717942863"),
        },

        {
           16,
           fromHex("0000000000000000000000000c9b2807"),
           fromHex("963a8a50ceb54d08e0dee0f1d0413dcf"),
           fromHex("2342bb9efa38542c0af75647f29f615d"),
        },
        {
           16,
           fromHex("0000000000000000000000002cbb4827"),
           fromHex("8665cc6b51b46b7e9b270296c3fd2053"),
           fromHex("2342bb9efa38542c0af75647f29f615d"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, BlockSize)
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, BlockSize)
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}
