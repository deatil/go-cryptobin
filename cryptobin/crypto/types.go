package crypto

import (
    "sync"
    "strconv"
)

// 类型
var TypeMultiple = NewTypes[Multiple, string](maxMultiple)
// 模式
var TypeMode = NewTypes[Mode, string](maxMode)
// 补码
var TypePadding = NewTypes[Padding, string](maxPadding)

// 构造函数
func NewTypes[N TypesName, D any](max N) *Types[N, D] {
    return &Types[N, D]{
        max:   max,
        names: make(map[N]func() D),
    }
}

type TypesName interface {
    Multiple | Mode | Padding
}

type Types[N TypesName, D any] struct {
    // 锁定
    mu sync.RWMutex

    // 最大值
    max N

    // 数据
    names map[N]func() D
}

// 生成新序列
func (this *Types[N, D]) Generate() N {
    old := this.max
    this.max++

    return old
}

// 设置
func (this *Types[N, D]) Add(name N, data func() D) *Types[N, D] {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.names[name] = data

    return this
}

func (this *Types[N, D]) Has(name N) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if _, ok := this.names[name]; ok {
        return true
    }

    return false
}

func (this *Types[N, D]) Get(name N) func() D {
    this.mu.RLock()
    defer this.mu.RUnlock()

    if data, ok := this.names[name]; ok {
        return data
    }

    return nil
}

// 删除
func (this *Types[N, D]) Remove(name N) *Types[N, D] {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.names, name)

    return this
}

func (this *Types[N, D]) Len() int {
    return len(this.names)
}

// ===================

// 加密类型
type Multiple uint

func (this Multiple) String() string {
    switch this {
        case Aes:
            return "Aes"
        case Des:
            return "Des"
        case TripleDes:
            return "TripleDes"
        case Twofish:
            return "Twofish"
        case Blowfish:
            return "Blowfish"
        case Tea:
            return "Tea"
        case Xtea:
            return "Xtea"
        case Cast5:
            return "Cast5"
        case RC2:
            return "RC2"
        case RC4:
            return "RC4"
        case RC5:
            return "RC5"
        case SM4:
            return "SM4"
        case Chacha20:
            return "Chacha20"
        case Chacha20poly1305:
            return "Chacha20poly1305"
        case Chacha20poly1305X:
            return "Chacha20poly1305X"
        case Xts:
            return "Xts"
        default:
            if TypeMultiple.Has(this) {
                return (TypeMultiple.Get(this))()
            }

            return "unknown multiple value " + strconv.Itoa(int(this))
    }
}

const (
    Aes Multiple = 1 + iota
    Des
    TripleDes
    Twofish
    Blowfish
    Tea
    Xtea
    Cast5
    RC2
    RC4
    RC5
    SM4
    Chacha20
    Chacha20poly1305
    Chacha20poly1305X
    Xts
    maxMultiple
)

// ===================

// 加密模式
type Mode uint

func (this Mode) String() string {
    switch this {
        case ECB:
            return "ECB"
        case CBC:
            return "CBC"
        case CFB:
            return "CFB"
        case CFB8:
            return "CFB8"
        case OFB:
            return "OFB"
        case OFB8:
            return "OFB8"
        case CTR:
            return "CTR"
        case GCM:
            return "GCM"
        case CCM:
            return "CCM"
        default:
            if TypeMode.Has(this) {
                return (TypeMode.Get(this))()
            }

            return "unknown mode value " + strconv.Itoa(int(this))
    }
}

const (
    ECB  Mode = 1 + iota
    CBC
    CFB
    CFB8
    OFB
    OFB8
    CTR
    GCM
    CCM
    maxMode
)

// ===================

// 补码类型
type Padding uint

func (this Padding) String() string {
    switch this {
        case NoPadding:
            return "NoPadding"
        case ZeroPadding:
            return "ZeroPadding"
        case PKCS5Padding:
            return "PKCS5Padding"
        case PKCS7Padding:
            return "PKCS7Padding"
        case X923Padding:
            return "X923Padding"
        case ISO10126Padding:
            return "ISO10126Padding"
        case ISO7816_4Padding:
            return "ISO7816_4Padding"
        case ISO97971Padding:
            return "ISO97971Padding"
        case TBCPadding:
            return "TBCPadding"
        case PKCS1Padding:
            return "PKCS1Padding"
        default:
            if TypePadding.Has(this) {
                return (TypePadding.Get(this))()
            }

            return "unknown padding value " + strconv.Itoa(int(this))
    }
}

const (
    NoPadding Padding = 1 + iota
    ZeroPadding
    PKCS5Padding
    PKCS7Padding
    X923Padding
    ISO10126Padding
    ISO7816_4Padding
    ISO97971Padding
    TBCPadding
    PKCS1Padding
    maxPadding
)
