package tool

import (
    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
)

type (
    // pkcs8 hash
    Pkcs8HmacHashMap = map[string]cryptobin_pkcs8.Hash
)

// pkcs8 hash 列表
var Pkcs8HmacHashes = Pkcs8HmacHashMap{
    "MD4":        cryptobin_pkcs8.MD4,
    "MD5":        cryptobin_pkcs8.MD5,
    "SHA1":       cryptobin_pkcs8.SHA1,
    "SHA224":     cryptobin_pkcs8.SHA224,
    "SHA256":     cryptobin_pkcs8.SHA256,
    "SHA384":     cryptobin_pkcs8.SHA384,
    "SHA512":     cryptobin_pkcs8.SHA512,
    "SHA512_224": cryptobin_pkcs8.SHA512_224,
    "SHA512_256": cryptobin_pkcs8.SHA512_256,
    "SM3":        cryptobin_pkcs8.SM3,
}

// 类型
func GetPkcs8HmacHash(typ string) cryptobin_pkcs8.Hash {
    sha, ok := Pkcs8HmacHashes[typ]
    if ok {
        return sha
    }

    return Pkcs8HmacHashes["SHA256"]
}
