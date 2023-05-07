package pbes1

import(
    "fmt"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/tool"
)

// 加密接口
type PEMCipher interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 值大小
    KeySize() int

    // 加密, 返回: [加密后数据, 参数, error]
    Encrypt(key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, params, ciphertext []byte) ([]byte, error)
}

var ciphers = make(map[string]func() PEMCipher)

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher func() PEMCipher) {
    ciphers[oid.String()] = cipher
}

// 获取加密
func GetCipher(oid string) (PEMCipher, error) {
    cipher, ok := ciphers[oid]
    if !ok {
        return nil, fmt.Errorf("pkcs: unsupported cipher (OID: %s)", oid)
    }

    newCipher := cipher()

    return newCipher, nil
}

// ===============

var newPadding = tool.NewPadding()

// 明文补码算法
func pkcs7Padding(text []byte, blockSize int) []byte {
    return newPadding.PKCS7Padding(text, blockSize)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) []byte {
    return newPadding.PKCS7UnPadding(src)
}

// 随机生成字符
func genRandom(num int) ([]byte, error) {
    return tool.GenRandom(num)
}
