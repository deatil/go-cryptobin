package bip0340

import (
    "io"
    "os"
    "log"
    "bufio"
    "testing"
    "strconv"
    "math/big"
    "encoding/csv"
    "crypto/sha256"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
)

func Test_Batch(t *testing.T) {
    u := 0

    var pks []*PublicKey
    var ms, sigs [][]byte
    f, _ := os.Open("testdata/test-vectors-multi.csv")

    reader := csv.NewReader(bufio.NewReader(f))
    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        } else if err != nil {
            log.Fatal(err)
        }

        _, err = strconv.ParseInt(record[0], 0, 0)
        if err != nil {
            continue
        }

        pkint, _ := new(big.Int).SetString(record[2], 16)
        pk := pad(pkint.Bytes(), 32)

        mint, _ := new(big.Int).SetString(record[4], 16)
        m := pad(mint.Bytes(), 32)

        sigint, _ := new(big.Int).SetString(record[5], 16)
        sig := pad(sigint.Bytes(), 64)

        expected, _ := strconv.ParseBool(record[6])
        if !expected {
            continue
        }

        u += 1

        pubBytes := append([]byte{byte(3)}, pk...)

        x, y := elliptic.UnmarshalCompressed(secp256k1.S256(), pubBytes)
        if x == nil || y == nil {
            t.Fatal("publicKey error")
        }

        pubkey := &PublicKey{
            Curve: secp256k1.S256(),
            X: x,
            Y: y,
        }

        pks = append(pks, pubkey)
        ms = append(ms, m)
        sigs = append(sigs, sig)
    }

    res := BatchVerify(pks, ms, sigs, sha256.New)
    if !res {
        t.Errorf("Batch verify failed")
    }
}
