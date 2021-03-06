package sm2

import(
    "errors"
)

// 生成公钥
func (this SM2) MakePublicKey() SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}
