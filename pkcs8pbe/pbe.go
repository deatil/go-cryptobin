package pkcs8pbe

import (
    "hash"
)

// 单个加密
func hashKey(h func() hash.Hash, key []byte) []byte {
    fn := h()
    fn.Write(key)
    data := fn.Sum(nil)

    return data
}

// 生成密钥
func derivedKey(password string, salt string, iter int, keyLen int, h func() hash.Hash) ([]byte, []byte) {
    key := hashKey(h, []byte(password + salt))

    for i := 0; i < iter - 1; i++ {
        key = hashKey(h, key)
    }

    return key[:keyLen], key[keyLen:]
}
