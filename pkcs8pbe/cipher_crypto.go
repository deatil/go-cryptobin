package pkcs8pbe

import (
    "crypto/des"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/asn1"
)

var (
    oidPbeWithMD5AndDES  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
    oidPbeWithSHA1AndDES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
    oidPbeWithSHAAnd3DES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
)

var PEMCipherMD5AndDES = CipherBlockCBC{
    cipherFunc:     des.NewCipher,
    hashFunc:       md5.New,
    keySize:        8,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD5AndDES,
}

var PEMCipherSHA1AndDES = CipherBlockCBC{
    cipherFunc:     des.NewCipher,
    hashFunc:       sha1.New,
    keySize:        8,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndDES,
}

var PEMCipherSHA1And3DES = CipherBlockCBC{
    cipherFunc:     des.NewTripleDESCipher,
    hashFunc:       sha256.New,
    keySize:        24,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHAAnd3DES,
}

func init() {
    AddCipher(oidPbeWithMD5AndDES, PEMCipherMD5AndDES)
    AddCipher(oidPbeWithSHA1AndDES, PEMCipherSHA1AndDES)
    AddCipher(oidPbeWithSHAAnd3DES, PEMCipherSHA1And3DES)
}
