package pkcs8pbe

import (
    "io"
    "hash"
    "errors"
    "crypto/des"
    "crypto/md5"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "crypto/cipher"
    "encoding/asn1"
    "encoding/pem"
)

// 迭代次数
const iterationCount = 2048

var (
    oidPbeWithMD5AndDES   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
    oidPbeWithSHA1AndDES  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
    oidPbeWithSHA1And3DES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
)

type PEMCipher int

// Possible values for the EncryptPEMBlock encryption algorithm.
const (
    _ PEMCipher = iota
    PEMCipherMD5AndDES
    PEMCipherSHA1AndDES
    PEMCipherSHA1And3DES
)

type rfc1423Algo struct {
    cipher     PEMCipher
    // 对称加密
    cipherFunc func(key []byte) (cipher.Block, error)
    // hash 摘要
    hashFunc   func() hash.Hash
    // 与 key 长度相关
    keySize    int
    // 与 iv 长度相关
    blockSize  int
    // oid
    oid        asn1.ObjectIdentifier
}

// 列表
var rfc1423Algos = []rfc1423Algo{
    {
        cipher:     PEMCipherMD5AndDES,
        cipherFunc: des.NewCipher,
        hashFunc:   md5.New,
        keySize:    8,
        blockSize:  des.BlockSize,
        oid:        oidPbeWithMD5AndDES,
    },
    {
        cipher:     PEMCipherSHA1AndDES,
        cipherFunc: des.NewCipher,
        hashFunc:   sha1.New,
        keySize:    8,
        blockSize:  des.BlockSize,
        oid:        oidPbeWithSHA1AndDES,
    },
    {
        cipher:     PEMCipherSHA1And3DES,
        cipherFunc: des.NewTripleDESCipher,
        hashFunc:   sha1.New,
        keySize:    24,
        blockSize:  des.BlockSize,
        oid:        oidPbeWithSHA1And3DES,
    },
}

// 结构体数据可以查看以下文档
// RFC5208 at https://tools.ietf.org/html/rfc5208
// RFC5958 at https://tools.ietf.org/html/rfc5958
type encryptedPrivateKeyInfo struct {
    EncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedData       []byte
}

// pbe 数据
type pbeParams struct {
    Salt           []byte
    IterationCount int
}

// 加密 PKCS8
func EncryptPKCS8PrivateKey(
    rand io.Reader,
    blockType string,
    data []byte,
    password []byte,
    alg PEMCipher,
) (*pem.Block, error) {
    cipher := cipherByKey(alg)
    if cipher == nil {
        return nil, errors.New("failed to encrypt PEM: unknown opts cipher")
    }

    salt := make([]byte, cipher.blockSize)
    if _, err := io.ReadFull(rand, salt); err != nil {
        return nil, errors.New(err.Error() + " failed to generate salt")
    }

    key, iv := derivedKey(string(password), string(salt), iterationCount, cipher.keySize, cipher.blockSize, cipher.hashFunc)

    en := CipherCBC{
        cipherFunc: cipher.cipherFunc,
        blockSize:  cipher.blockSize,
    }

    encrypted, err := en.Encrypt(key, iv, data)
    if err != nil {
        return nil, err
    }

    // 生成 asn1 数据开始
    marshalledParams, err := asn1.Marshal(pbeParams{
        Salt:           salt,
        IterationCount: iterationCount,
    })
    if err != nil {
        return nil, err
    }

    encryptionAlgorithm := pkix.AlgorithmIdentifier{
        Algorithm:  cipher.oid,
        Parameters: asn1.RawValue{
            FullBytes: marshalledParams,
        },
    }

    // 生成 ans1 数据
    pki := encryptedPrivateKeyInfo{
        EncryptionAlgorithm: encryptionAlgorithm,
        EncryptedData:       encrypted,
    }

    b, err := asn1.Marshal(pki)
    if err != nil {
        return nil, errors.New(err.Error() + " error marshaling encrypted key")
    }

    return &pem.Block{
        Type:  blockType,
        Bytes: b,
    }, nil
}

// 解出 PKCS8 密钥
func DecryptPKCS8PrivateKey(data, password []byte) ([]byte, error) {
    var pki encryptedPrivateKeyInfo
    if _, err := asn1.Unmarshal(data, &pki); err != nil {
        return nil, errors.New(err.Error() + " failed to unmarshal private key")
    }

    var params pbeParams
    if _, err := asn1.Unmarshal(pki.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 parameters")
    }

    cipher := cipherByOid(pki.EncryptionAlgorithm.Algorithm)

    key, iv := derivedKey(string(password), string(params.Salt), params.IterationCount, cipher.keySize, cipher.blockSize, cipher.hashFunc)

    // 加密的数据
    data = pki.EncryptedData

    en := CipherCBC{
        cipherFunc: cipher.cipherFunc,
        blockSize:  cipher.blockSize,
    }

    decryptedKey, err := en.Decrypt(key, iv, data)
    if err != nil {
        return nil, err
    }

    return decryptedKey, nil
}

// 解出 PEM 块
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
    if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
        return x509.DecryptPEMBlock(block, password)
    }

    // PKCS#8 header defined in RFC7468 section 11
    if block.Type == "ENCRYPTED PRIVATE KEY" {
        return DecryptPKCS8PrivateKey(block.Bytes, password)
    }

    return nil, errors.New("unsupported encrypted PEM")
}

func cipherByKey(key PEMCipher) *rfc1423Algo {
    for i := range rfc1423Algos {
        alg := &rfc1423Algos[i]
        if alg.cipher == key {
            return alg
        }
    }

    return nil
}

func cipherByOid(oid asn1.ObjectIdentifier) *rfc1423Algo {
    for i := range rfc1423Algos {
        alg := &rfc1423Algos[i]
        if oid.Equal(alg.oid) {
            return alg
        }
    }

    return nil
}

