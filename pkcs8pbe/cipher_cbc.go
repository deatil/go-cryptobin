package pkcs8pbe

import (
    "errors"
    "crypto/cipher"
)

// cbc 模式加密
type CipherCBC struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    blockSize  int
}

// 加密
func (this CipherCBC) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, errors.New("pkcs8:" + err.Error() + " failed to create cipher")
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    return encrypted, nil
}

// 解密
func (this CipherCBC) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
    plaintext := make([]byte, len(ciphertext))

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 判断数据是否为填充数据
    blockSize := block.BlockSize()
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs8: invalid padding")
    }

    // 解析加密数据
    plaintext = pkcs7UnPadding(plaintext)

    return plaintext, nil
}
