package sm2

import (
    "errors"
    "math/big"
    "crypto/rand"
    "encoding/asn1"

    "github.com/tjfoc/gmsm/sm2"
    
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥签名
func (this SM2) Sign() SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    this.paredData, this.Error = this.privateKey.Sign(rand.Reader, this.data, nil)

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this SM2) Very(data []byte) SM2 {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    this.veryed = this.publicKey.Verify(data, this.data)

    return this
}

// ===============

type sm2Signature struct {
    R, S *big.Int
}

// 私钥签名
func (this SM2) SignAsn1(uid []byte) SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    r, s, err := sm2.Sm2Sign(this.privateKey, this.data, uid, rand.Reader)
    if err != nil {
        this.Error = err

        return this
    }

    this.paredData, this.Error = asn1.Marshal(sm2Signature{r, s})

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this SM2) VerifyAsn1(data []byte, uid []byte) SM2 {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    var sm2Sign sm2Signature
    _, err := asn1.Unmarshal(this.data, &sm2Sign)
    if err != nil {
        this.Error = err

        return this
    }

    this.veryed = sm2.Sm2Verify(this.publicKey, data, uid, sm2Sign.R, sm2Sign.S)

    return this
}

// ===============

// 私钥签名
// 兼容[招行]
func (this SM2) SignHex(uid []byte) SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    r, s, err := sm2.Sm2Sign(this.privateKey, this.data, uid, rand.Reader)
    if err != nil {
        this.Error = err
        return this
    }

    encoding := cryptobin_tool.NewEncoding()

    rHex := encoding.HexEncode(r.Bytes())
    sHex := encoding.HexEncode(s.Bytes())

    sign := encoding.HexPadding(rHex, 64) + encoding.HexPadding(sHex, 64)

    this.paredData, this.Error = encoding.HexDecode(sign)

    return this
}

// 公钥验证
// 兼容[招行]
// 使用原始数据[data]对比签名后数据
func (this SM2) VerifyHex(data []byte, uid []byte) SM2 {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    signData := cryptobin_tool.NewEncoding().HexEncode(this.data)

    r, _ := new(big.Int).SetString(signData[:64], 16)
    s, _ := new(big.Int).SetString(signData[64:], 16)

    this.veryed = sm2.Sm2Verify(this.publicKey, data, uid, r, s)

    return this
}
