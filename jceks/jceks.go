package jceks

import (
    "io"
    "bytes"
)

// 编码
type JCEKS struct {
    // 私钥加证书
    privateKeys  map[string]privateKeyEntry

    // 证书
    trustedCerts map[string]trustedCertEntry

    // 密钥
    secretKeys   map[string]secretKeyEntry

    // 数量统计
    count        int

    // 解析后数据
    entries      map[string]interface{}
}

// 构造函数
func NewJCEKS() *JCEKS {
    return &JCEKS{
        privateKeys:  make(map[string]privateKeyEntry),
        trustedCerts: make(map[string]trustedCertEntry),
        secretKeys:   make(map[string]secretKeyEntry),
        count:        0,
    }
}

// LoadJceksFromReader loads the key store from the specified file.
func LoadJceksFromReader(reader io.Reader, password string) (*JCEKS, error) {
    ks := &JCEKS{
        entries: make(map[string]interface{}),
    }

    err := ks.Parse(reader, password)
    if err != nil {
        return nil, err
    }

    return ks, err
}

// LoadJceksFromBytes loads the key store from the bytes data.
func LoadJceksFromBytes(data []byte, password string) (*JCEKS, error) {
    buf := bytes.NewReader(data)

    return LoadFromReader(buf, password)
}

// 别名
var LoadFromReader = LoadJceksFromReader
var LoadFromBytes  = LoadJceksFromBytes
var NewJceksEncode = NewJCEKS
