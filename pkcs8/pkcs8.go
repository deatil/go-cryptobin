package pkcs8

import (
    "io"
    "fmt"
    "errors"
    "crypto"
    "crypto/aes"
    "crypto/des"
    "crypto/x509"
    "crypto/x509/pkix"
    "crypto/cipher"
    "encoding/asn1"
    "encoding/pem"
)

// PBKDF2SaltSize is the default size of the salt for PBKDF2, 128-bit salt.
const PBKDF2SaltSize = 16

// PBKDF2Iterations is the default number of iterations for PBKDF2, 100k
// iterations. Nist recommends at least 10k, 1Passsword uses 100k.
const PBKDF2Iterations = 10000

var (
    // key derivation functions
    oidRSADSI         = asn1.ObjectIdentifier{1, 2, 840, 113549}
    oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

    // 加密方式
    oidEncryptionAlgorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 3}
    oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
    oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}

    oidAES       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1}
    oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
    oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
    oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// 结构体数据可以查看以下文档
// RFC5208 at https://tools.ietf.org/html/rfc5208
// RFC5958 at https://tools.ietf.org/html/rfc5958
type encryptedPrivateKeyInfo struct {
    EncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedData       []byte
}

// pbes2 数据
type pbes2Params struct {
    KeyDerivationFunc pkix.AlgorithmIdentifier
    EncryptionScheme  pkix.AlgorithmIdentifier
}

// 设置接口
type KDFOpts interface {
    DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error)
    GetSaltSize() int
    OID() asn1.ObjectIdentifier
}

// 数据接口
type KDFParameters interface {
    DeriveKey(password []byte, size int) (key []byte, err error)
}

// 配置
type Opts struct {
    KDFOpts KDFOpts
}

// 默认配置
var DefaultOpts = Opts{
    KDFOpts: PBKDF2Opts{
        SaltSize:       PBKDF2SaltSize,
        IterationCount: PBKDF2Iterations,
        HMACHash:       crypto.SHA256,
    },
}

// PEM 块
type rfc1423Algo struct {
    cipher     x509.PEMCipher
    name       string
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    blockSize  int
    identifier asn1.ObjectIdentifier
}

// PEM 块列表
var rfc1423Algos = []rfc1423Algo{
    {
        cipher:     x509.PEMCipherDES,
        name:       "DES-CBC",
        cipherFunc: des.NewCipher,
        keySize:    8,
        blockSize:  des.BlockSize,
        identifier: oidDESCBC,
    },
    {
        cipher:     x509.PEMCipher3DES,
        name:       "DES-EDE3-CBC",
        cipherFunc: des.NewTripleDESCipher,
        keySize:    24,
        blockSize:  des.BlockSize,
        identifier: oidDESEDE3CBC,
    },
    {
        cipher:     x509.PEMCipherAES128,
        name:       "AES-128-CBC",
        cipherFunc: aes.NewCipher,
        keySize:    16,
        blockSize:  aes.BlockSize,
        identifier: oidAES128CBC,
    },
    {
        cipher:     x509.PEMCipherAES192,
        name:       "AES-192-CBC",
        cipherFunc: aes.NewCipher,
        keySize:    24,
        blockSize:  aes.BlockSize,
        identifier: oidAES192CBC,
    },
    {
        cipher:     x509.PEMCipherAES256,
        name:       "AES-256-CBC",
        cipherFunc: aes.NewCipher,
        keySize:    32,
        blockSize:  aes.BlockSize,
        identifier: oidAES256CBC,
    },
}

// 最加数据为新的 Identifier
func AppendOID(b asn1.ObjectIdentifier, v ...int) asn1.ObjectIdentifier {
    n := make(asn1.ObjectIdentifier, len(b), len(b) + len(v))
    copy(n, b)
    return append(n, v...)
}

// 添加 rfc1423Algo
func AddRfc1423Algo(value rfc1423Algo) {
    rfc1423Algos = append(rfc1423Algos, value)
}

func cipherByKey(key x509.PEMCipher) *rfc1423Algo {
    for i := range rfc1423Algos {
        alg := &rfc1423Algos[i]
        if alg.cipher == key {
            return alg
        }
    }

    return nil
}

func cipherById(id asn1.ObjectIdentifier) *rfc1423Algo {
    for i := range rfc1423Algos {
        alg := &rfc1423Algos[i]
        if alg.identifier.Equal(id) {
            return alg
        }
    }

    return nil
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

// 解出 PKCS8 密钥
// 加密方式: AES-128-CBC | AES-192-CBC | AES-256-CBC | DES | 3DES
func DecryptPKCS8PrivateKey(data, password []byte) ([]byte, error) {
    var pki encryptedPrivateKeyInfo
    if _, err := asn1.Unmarshal(data, &pki); err != nil {
        return nil, errors.New(err.Error() + " failed to unmarshal private key")
    }

    if !pki.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
        return nil, errors.New("unsupported encrypted PEM: only PBES2 is supported")
    }

    var params pbes2Params
    if _, err := asn1.Unmarshal(pki.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 parameters")
    }

    if !params.KeyDerivationFunc.Algorithm.Equal(oidPKCS5PBKDF2) {
        return nil, errors.New("unsupported encrypted PEM: only PBKDF2 is supported")
    }

    var iv []byte
    if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 iv")
    }

    // 解析出数据
    var kdfParam pbkdf2Params
    if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdfParam); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 parameters")
    }

    ciph := cipherById(params.EncryptionScheme.Algorithm)
    if ciph == nil {
        return nil, errors.New(fmt.Sprintf("unsupported encrypted PEM: unknown algorithm %v", params.EncryptionScheme.Algorithm))
    }

    // AES-128-CBC, AES-192-CBC, AES-256-CBC
    // DES, TripleDES
    symkey, err := kdfParam.DeriveKey(password, ciph.keySize)
    if err != nil {
        return nil, err
    }

    block, err := ciph.cipherFunc(symkey)
    if err != nil {
        return nil, err
    }

    data = pki.EncryptedData

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(data, data)

    // 解析加密数据
    blockSize := block.BlockSize()
    dlen := len(data)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("error decrypting PEM: invalid padding")
    }

    last := int(data[dlen-1])
    if dlen < last {
        return nil, x509.IncorrectPasswordError
    }
    if last == 0 || last > blockSize {
        return nil, x509.IncorrectPasswordError
    }

    for _, val := range data[dlen-last:] {
        if int(val) != last {
            return nil, x509.IncorrectPasswordError
        }
    }

    return data[:dlen-last], nil
}

// 加密 PKCS8
func EncryptPKCS8PrivateKey(
    rand io.Reader,
    blockType string,
    data []byte,
    password []byte,
    alg x509.PEMCipher,
    opts ...any,
) (*pem.Block, error) {
    ciph := cipherByKey(alg)
    if ciph == nil {
        return nil, errors.New(fmt.Sprintf("failed to encrypt PEM: unknown algorithm %v", alg))
    }

    var kdfOpt any
    if len(opts) > 0 {
        kdfOpt = opts[0]
    } else {
        kdfOpt = DefaultOpts
    }

    var opt *Opts

    // 断言类型
    switch optData := kdfOpt.(type) {
        case Opts:
            opt = &optData
        case string:
            h, err := GetHash(optData)
            if err != nil {
                return nil, err
            }

            opt = &Opts{
                KDFOpts: PBKDF2Opts{
                    SaltSize:       PBKDF2SaltSize,
                    IterationCount: PBKDF2Iterations,
                    HMACHash:       h,
                },
            }
    }

    salt := make([]byte, opt.KDFOpts.GetSaltSize())
    if _, err := io.ReadFull(rand, salt); err != nil {
        return nil, errors.New(err.Error() + " failed to generate salt")
    }

    iv := make([]byte, ciph.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, errors.New(err.Error() + " failed to generate IV")
    }

    key, kdfParams, err := opt.KDFOpts.DeriveKey(password, salt, ciph.keySize)
    if err != nil {
        return nil, err
    }

    block, err := ciph.cipherFunc(key)
    if err != nil {
        return nil, errors.New(err.Error() + " failed to create cipher")
    }

    enc := cipher.NewCBCEncrypter(block, iv)
    pad := ciph.blockSize - len(data)%ciph.blockSize
    encrypted := make([]byte, len(data), len(data)+pad)

    copy(encrypted, data)
    // See RFC 1423, section 1.1
    for i := 0; i < pad; i++ {
        encrypted = append(encrypted, byte(pad))
    }
    enc.CryptBlocks(encrypted, encrypted)

    // 生成 asn1 数据开始
    marshalledParams, err := asn1.Marshal(kdfParams)
    if err != nil {
        return nil, err
    }

    keyDerivationFunc := pkix.AlgorithmIdentifier{
        Algorithm:  oidPKCS5PBKDF2,
        Parameters: asn1.RawValue{
            FullBytes: marshalledParams,
        },
    }

    marshalledIV, err := asn1.Marshal(iv)
    if err != nil {
        return nil, err
    }

    encryptionScheme := pkix.AlgorithmIdentifier{
        Algorithm:  ciph.identifier,
        Parameters: asn1.RawValue{
            FullBytes: marshalledIV,
        },
    }

    encryptionAlgorithmParams := pbes2Params{
        EncryptionScheme:  encryptionScheme,
        KeyDerivationFunc: keyDerivationFunc,
    }
    marshalledEncryptionAlgorithmParams, err := asn1.Marshal(encryptionAlgorithmParams)
    if err != nil {
        return nil, err
    }

    encryptionAlgorithm := pkix.AlgorithmIdentifier{
        Algorithm:  oidPBES2,
        Parameters: asn1.RawValue{
            FullBytes: marshalledEncryptionAlgorithmParams,
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
