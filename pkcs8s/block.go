package pkcs8s

import (
    "io"
    "errors"
    "crypto/x509"
    "encoding/pem"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
)

// 加密 pem
func EncryptPEMBlock(
    rand      io.Reader,
    blockType string,
    data      []byte,
    password  []byte,
    cipher    any,
) (*pem.Block, error) {
    switch c := cipher.(type) {
        case cryptobin_pkcs8.Cipher:
            if _, err := cryptobin_pkcs8.GetCipher(c.OID().String()); err == nil {
                opts := cryptobin_pkcs8.DefaultOpts
                opts.Cipher = c

                return cryptobin_pkcs8.EncryptPKCS8PrivateKey(rand, blockType, data, password, opts)
            }

            return cryptobin_pkcs8pbe.EncryptPKCS8PrivateKey(rand, blockType, data, password, c)

        case cryptobin_pkcs8.Opts:
            if _, err := cryptobin_pkcs8pbe.GetCipher(c.Cipher.OID().String()); err == nil {
                return cryptobin_pkcs8pbe.EncryptPKCS8PrivateKey(rand, blockType, data, password, c.Cipher)
            }

            return cryptobin_pkcs8.EncryptPKCS8PrivateKey(rand, blockType, data, password, c)
    }

    return nil, errors.New("pkcs8: unsupported cipher")
}

// 解出 PEM 块
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
    if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
        return x509.DecryptPEMBlock(block, password)
    }

    // PKCS#8 header defined in RFC7468 section 11
    if block.Type == "ENCRYPTED PRIVATE KEY" {
        var blockDecrypted []byte
        var err error

        if blockDecrypted, err = cryptobin_pkcs8.DecryptPKCS8PrivateKey(block.Bytes, password); err == nil {
            return blockDecrypted, nil
        }

        if blockDecrypted, err = cryptobin_pkcs8pbe.DecryptPKCS8PrivateKey(block.Bytes, password); err == nil {
            return blockDecrypted, nil
        }
    }

    return nil, errors.New("pkcs8: unsupported encrypted PEM")
}
