package lms

import (
    "fmt"
    "sync"
)

// TypeDataName interface
type TypeDataName interface {
    ~uint32 | ~int
}

// TypeParams
type TypeParams[N TypeDataName, M any] struct {
    // 读写锁
    mu sync.RWMutex

    // 列表
    data map[N]func() M
}

func NewTypeParams[N TypeDataName, M any]() *TypeParams[N, M] {
    return &TypeParams[N, M] {
        data: make(map[N]func() M),
    }
}

// 添加类型
func (this *TypeParams[N, M]) AddParam(typ N, fn func() M) {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.data[typ] = fn
}

// 获取类型
func (this *TypeParams[N, M]) GetParam(typ N) (func() M, error) {
    this.mu.RLock()
    defer this.mu.RUnlock()

    param, ok := this.data[typ]
    if !ok {
        err := fmt.Errorf("lms: unsupported param (ID: %d)", typ)
        return nil, err
    }

    return param, nil
}

// 全部
func (this *TypeParams[N, M]) AllParams() map[N]func() M {
    this.mu.RLock()
    defer this.mu.RUnlock()

    return this.data
}
