package jceks

const (
    UberVersionV1 = 1
)

// UBER
type UBER struct {
    BKS
}

// 构造函数
func NewUBER() *UBER {
    uber := &UBER{
        BKS{
            entries: make(map[string]any),
        },
    }

    return uber
}

// LoadUber loads the key store from the bytes data.
func LoadUber(data []byte, password string) (*UBER, error) {
    uber := &UBER{
        BKS{
            entries: make(map[string]any),
        },
    }

    err := uber.Parse(data, password)
    if err != nil {
        return nil, err
    }

    return uber, err
}

// 别名
var NewUberEncode = NewUBER
