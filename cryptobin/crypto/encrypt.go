package crypto

import (
    "fmt"
)

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    if !UseEncrypt.Has(this.multiple) {
        err := fmt.Errorf("Cryptobin: Multiple [%s] is error.", this.multiple)
        return this.AppendError(err)
    }

    // 类型
    newEncrypt := UseEncrypt.Get(this.multiple)

    dst, err := newEncrypt().Encrypt(this.data, NewConfig(this))
    if err != nil {
        return this.AppendError(err)
    }

    // 补码模式
    this.parsedData = dst

    return this
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    if !UseEncrypt.Has(this.multiple) {
        err := fmt.Errorf("Cryptobin: Multiple [%s] is error.", this.multiple)
        return this.AppendError(err)
    }

    // 类型
    newEncrypt := UseEncrypt.Get(this.multiple)

    dst, err := newEncrypt().Decrypt(this.data, NewConfig(this))
    if err != nil {
        return this.AppendError(err)
    }

    // 补码模式
    this.parsedData = dst

    return this
}

// ====================

// 方法加密
func (this Cryptobin) FuncEncrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this)
}

// 方法解密
func (this Cryptobin) FuncDecrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this)
}
