package lms

import (
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

type LmotsType uint32

const (
    LMOTS_RESERVED      LmotsType = 0
    LMOTS_SHA256_N32_W1 LmotsType = 1
    LMOTS_SHA256_N32_W2 LmotsType = 2
    LMOTS_SHA256_N32_W4 LmotsType = 3
    LMOTS_SHA256_N32_W8 LmotsType = 4

    LMOTS_SM3_N32_W1 LmotsType = 11
    LMOTS_SM3_N32_W2 LmotsType = 12
    LMOTS_SM3_N32_W4 LmotsType = 13
    LMOTS_SM3_N32_W8 LmotsType = 14
)

// ILmotsParam represents a specific instance of LM-OTS
type ILmotsParam interface {
    GetType() LmotsType
    SigLength() uint64
    Params() LmotsParam
}

type LmotsParam struct {
    Type    LmotsType
    Hash    Hasher
    N       uint64
    W       ByteWindow
    P       uint64
    LS      uint64
    SIG_LEN uint64
}

// Returns a uint32 of the same value as the LmotsType
func (this LmotsParam) GetType() LmotsType {
    return this.Type
}

// Returns the expected byte length of a given LM-OTS signature algorithm
func (this LmotsParam) SigLength() uint64 {
    return this.SIG_LEN
}

// Returns a Params
func (this LmotsParam) Params() LmotsParam {
    return this
}

// ===============

// 默认
var defaultLmotsParams = NewTypeParams[LmotsType, ILmotsParam]()

// 添加类型
func AddLmotsParam(typ LmotsType, fn func() ILmotsParam) {
    defaultLmotsParams.AddParam(typ, fn)
}

// 获取类型
func GetLmotsParam(typ LmotsType) (func() ILmotsParam, error) {
    return defaultLmotsParams.GetParam(typ)
}

// 全部
func AllLmotsParams() map[LmotsType]func() ILmotsParam {
    return defaultLmotsParams.AllParams()
}

// ===============

var (
    LMOTS_SHA256_N32_W1_Param = LmotsParam{
        Type:    LMOTS_SHA256_N32_W1,
        Hash:    sha256.New,
        N:       sha256.Size,
        W:       WINDOW_W1,
        P:       265,
        LS:      7,
        SIG_LEN: 8516,
    }
    LMOTS_SHA256_N32_W2_Param = LmotsParam{
        Type:    LMOTS_SHA256_N32_W2,
        Hash:    sha256.New,
        N:       sha256.Size,
        W:       WINDOW_W2,
        P:       133,
        LS:      6,
        SIG_LEN: 4292,
    }
    LMOTS_SHA256_N32_W4_Param = LmotsParam{
        Type:    LMOTS_SHA256_N32_W4,
        Hash:    sha256.New,
        N:       sha256.Size,
        W:       WINDOW_W4,
        P:       67,
        LS:      4,
        SIG_LEN: 2180,
    }
    LMOTS_SHA256_N32_W8_Param = LmotsParam{
        Type:    LMOTS_SHA256_N32_W8,
        Hash:    sha256.New,
        N:       sha256.Size,
        W:       WINDOW_W8,
        P:       34,
        LS:      0,
        SIG_LEN: 1124,
    }

    // SM3 hash
    LMOTS_SM3_N32_W1_Param = LmotsParam{
        Type:    LMOTS_SM3_N32_W1,
        Hash:    sm3.New,
        N:       sm3.Size,
        W:       WINDOW_W1,
        P:       265,
        LS:      7,
        SIG_LEN: 8516,
    }
    LMOTS_SM3_N32_W2_Param = LmotsParam{
        Type:    LMOTS_SM3_N32_W2,
        Hash:    sm3.New,
        N:       sm3.Size,
        W:       WINDOW_W2,
        P:       133,
        LS:      6,
        SIG_LEN: 4292,
    }
    LMOTS_SM3_N32_W4_Param = LmotsParam{
        Type:    LMOTS_SM3_N32_W4,
        Hash:    sm3.New,
        N:       sm3.Size,
        W:       WINDOW_W4,
        P:       67,
        LS:      4,
        SIG_LEN: 2180,
    }
    LMOTS_SM3_N32_W8_W8_Param = LmotsParam{
        Type:    LMOTS_SM3_N32_W8,
        Hash:    sm3.New,
        N:       sm3.Size,
        W:       WINDOW_W8,
        P:       34,
        LS:      0,
        SIG_LEN: 1124,
    }
)

func init() {
    AddLmotsParam(LMOTS_SHA256_N32_W1_Param.Type, func() ILmotsParam {
        return LMOTS_SHA256_N32_W1_Param
    })
    AddLmotsParam(LMOTS_SHA256_N32_W2_Param.Type, func() ILmotsParam {
        return LMOTS_SHA256_N32_W2_Param
    })
    AddLmotsParam(LMOTS_SHA256_N32_W4_Param.Type, func() ILmotsParam {
        return LMOTS_SHA256_N32_W4_Param
    })
    AddLmotsParam(LMOTS_SHA256_N32_W8_Param.Type, func() ILmotsParam {
        return LMOTS_SHA256_N32_W8_Param
    })

    // SM3 hash
    AddLmotsParam(LMOTS_SM3_N32_W1_Param.Type, func() ILmotsParam {
        return LMOTS_SM3_N32_W1_Param
    })
    AddLmotsParam(LMOTS_SM3_N32_W2_Param.Type, func() ILmotsParam {
        return LMOTS_SM3_N32_W2_Param
    })
    AddLmotsParam(LMOTS_SM3_N32_W4_Param.Type, func() ILmotsParam {
        return LMOTS_SM3_N32_W4_Param
    })
    AddLmotsParam(LMOTS_SM3_N32_W8_W8_Param.Type, func() ILmotsParam {
        return LMOTS_SM3_N32_W8_W8_Param
    })

}
