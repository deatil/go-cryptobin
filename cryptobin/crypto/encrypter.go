package crypto

import (
    "sync"
)

// 加密解密
var UseEncrypt = NewEncrypter()

// 构造函数
func NewEncrypter() *Encrypter {
    return &Encrypter{
        data: make(map[Multiple]func() IEncrypt),
    }
}

/**
 * 加密解密
 *
 * @create 2023-3-30
 * @author deatil
 */
type Encrypter struct {
    // 锁定
    mu sync.RWMutex

    // 数据
    data map[Multiple]func() IEncrypt
}

// 设置
func (this *Encrypter) Add(name Multiple, data func() IEncrypt) *Encrypter {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.data[name] = data

    return this
}

func (this *Encrypter) Has(name Multiple) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, ok := this.data[name]; ok {
        return true
    }

    return false
}

func (this *Encrypter) Get(name Multiple) func() IEncrypt {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if data, ok := this.data[name]; ok {
        return data
    }

    return nil
}

// 删除
func (this *Encrypter) Remove(name Multiple) *Encrypter {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.data, name)

    return this
}

func (this *Encrypter) Names() []Multiple {
    names := make([]Multiple, 0)
    for name, _ := range this.data {
        names = append(names, name)
    }

    return names
}

func (this *Encrypter) Len() int {
    return len(this.data)
}
