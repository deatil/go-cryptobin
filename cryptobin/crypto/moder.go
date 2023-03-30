package crypto

import (
    "sync"
)

// 模式
var UseMode = NewModer()

// 构造函数
func NewModer() *Moder {
    return &Moder{
        data: make(map[Mode]func() IMode),
    }
}

/**
 * 模式
 *
 * @create 2023-3-30
 * @author deatil
 */
type Moder struct {
    // 锁定
    mu sync.RWMutex

    // 数据
    data map[Mode]func() IMode
}

// 设置
func (this *Moder) Add(name Mode, f func() IMode) *Moder {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.data[name] = f

    return this
}

func (this *Moder) Has(name Mode) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, ok := this.data[name]; ok {
        return true
    }

    return false
}

func (this *Moder) Get(name Mode) func() IMode {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if data, ok := this.data[name]; ok {
        return data
    }

    return nil
}

// 删除
func (this *Moder) Remove(name Mode) *Moder {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.data, name)

    return this
}

func (this *Moder) Names() []Mode {
    names := make([]Mode, 0)
    for name, _ := range this.data {
        names = append(names, name)
    }

    return names
}

func (this *Moder) Len() int {
    return len(this.data)
}
