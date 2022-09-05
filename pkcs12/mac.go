package pkcs12

import (
    "hash"
    "crypto/hmac"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/x509/pkix"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/kdf/pbkdf"
)

type macData struct {
    Mac        digestInfo
    MacSalt    []byte
    Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
    Algorithm pkix.AlgorithmIdentifier
    Digest    []byte
}

var (
    oidSHA1   = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
    oidSHA256 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
)

func verifyMac(macData *macData, message, password []byte) error {
    var hFn func() hash.Hash
    var key []byte

    switch {
        case macData.Mac.Algorithm.Algorithm.Equal(oidSHA1):
            hFn = sha1.New
            key = pbkdf.Key(sha1.New, 20, 64, macData.MacSalt, password, macData.Iterations, 3, 20)
        case macData.Mac.Algorithm.Algorithm.Equal(oidSHA256):
            hFn = sha256.New
            key = pbkdf.Key(sha256.New, 32, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
        default:
            return NotImplementedError("unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
    }

    mac := hmac.New(hFn, key)
    mac.Write(message)
    expectedMAC := mac.Sum(nil)

    if !hmac.Equal(macData.Mac.Digest, expectedMAC) {
        return ErrIncorrectPassword
    }

    return nil
}

func computeMac(macData *macData, message, password []byte) error {
    if !macData.Mac.Algorithm.Algorithm.Equal(oidSHA1) {
        return NotImplementedError("unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
    }

    key := pbkdf.Key(sha1.New, 20, 64, macData.MacSalt, password, macData.Iterations, 3, 20)

    mac := hmac.New(sha1.New, key)
    mac.Write(message)
    macData.Mac.Digest = mac.Sum(nil)

    return nil
}
