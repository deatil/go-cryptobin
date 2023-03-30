package crypto

import (
    "sync"
)

// 补码
var UsePadding = NewPaddinger()

// 构造函数
func NewPaddinger() *Paddinger {
    return &Paddinger{
        data: make(map[Padding]func() IPadding),
    }
}

/**
 * 补码
 *
 * @create 2023-3-30
 * @author deatil
 */
type Paddinger struct {
    // 锁定
    mu sync.RWMutex

    // 数据
    data map[Padding]func() IPadding
}

// 设置
func (this *Paddinger) Add(name Padding, data func() IPadding) *Paddinger {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.data[name] = data

    return this
}

func (this *Paddinger) Has(name Padding) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, ok := this.data[name]; ok {
        return true
    }

    return false
}

func (this *Paddinger) Get(name Padding) func() IPadding {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if data, ok := this.data[name]; ok {
        return data
    }

    return nil
}

// 删除
func (this *Paddinger) Remove(name Padding) *Paddinger {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.data, name)

    return this
}

func (this *Paddinger) Names() []Padding {
    names := make([]Padding, 0)
    for name, _ := range this.data {
        names = append(names, name)
    }

    return names
}

func (this *Paddinger) Len() int {
    return len(this.data)
}
