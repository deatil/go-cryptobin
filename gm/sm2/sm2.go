package sm2

import (
    "io"
    "bytes"
    "errors"
    "strings"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

var defaultUid = []byte{
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
}

var errZeroParam = errors.New("zero parameter")

// 加密模式
type Mode uint

const (
    C1C3C2 Mode = 0 + iota
    C1C2C3 = 1
)

var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

type sm2Signature struct {
    R, S *big.Int
}

type EncrypterOpts struct {
    Mode Mode
}

type SignerOpts struct {
    Uid []byte
}

func (opt SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

type PublicKey struct {
    elliptic.Curve
    X, Y *big.Int
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.Curve == xx.Curve &&
        bigIntEqual(pub.X, xx.X) &&
        bigIntEqual(pub.Y, xx.Y)
}

func (pub *PublicKey) Verify(msg []byte, sign []byte, opts crypto.SignerOpts) bool {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    var sm2Sign sm2Signature
    _, err := asn1.Unmarshal(sign, &sm2Sign)
    if err != nil {
        return false
    }

    return Sm2Verify(pub, msg, uid, sm2Sign.R, sm2Sign.S)
}

func (pub *PublicKey) VerifyHex(msg []byte, sign []byte, opts crypto.SignerOpts) bool {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    signData := hex.EncodeToString(sign)

    r, _ := new(big.Int).SetString(signData[:64], 16)
    s, _ := new(big.Int).SetString(signData[64:], 16)

    return Sm2Verify(pub, msg, uid, r, s)
}

func (pub *PublicKey) Encrypt(random io.Reader, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return Encrypt(random, pub, data, mode)
}

func (pub *PublicKey) EncryptAsn1(random io.Reader, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return EncryptAsn1(random, pub, data, mode)
}

type PrivateKey struct {
    PublicKey
    D *big.Int
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.PublicKey.Equal(&xx.PublicKey) &&
        bigIntEqual(priv.D, xx.D)
}

// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s
func (priv *PrivateKey) Sign(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    r, s, err := Sm2Sign(random, priv, msg, uid)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(sm2Signature{r, s})
}

func (priv *PrivateKey) SignHex(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    r, s, err := Sm2Sign(random, priv, msg, uid)
    if err != nil {
        return nil, err
    }

    rHex := hex.EncodeToString(r.Bytes())
    sHex := hex.EncodeToString(s.Bytes())

    sign := hexPadding(rHex, 64) + hexPadding(sHex, 64)

    return hex.DecodeString(sign)
}

// crypto.Decrypter
func (priv *PrivateKey) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return Decrypt(priv, msg, mode)
}

func (priv *PrivateKey) DecryptAsn1(data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return DecryptAsn1(priv, data, mode)
}

func GenerateKey(random io.Reader) (*PrivateKey, error) {
    c := P256Sm2()

    if random == nil {
        random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
    }

    params := c.Params()

    b := make([]byte, params.BitSize/8+8)

    _, err := io.ReadFull(random, b)
    if err != nil {
        return nil, err
    }

    k := new(big.Int).SetBytes(b)
    n := new(big.Int).Sub(params.N, two)

    k.Mod(k, n)
    k.Add(k, one)

    priv := new(PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    return priv, nil
}

// 根据私钥明文16进制明文初始化私钥
func NewPrivateKey(Dhex string) (*PrivateKey, error) {
    c := P256Sm2()

    d, err := hex.DecodeString(Dhex)
    if err != nil{
        return nil, err
    }

    k:= new(big.Int).SetBytes(d)

    params := c.Params()

    one := new(big.Int).SetInt64(1)
    n := new(big.Int).Sub(params.N, one)
    if k.Cmp(n) >= 0{
      return nil, errors.New("privateKey's D is overflow.")
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    return priv, nil
}

// 输出私钥明文
func ToPrivateKey(key *PrivateKey) string {
    return key.D.Text(16)
}

// 根据公钥16进制明文初始化公钥
func NewPublicKey(Qhex string) (*PublicKey, error) {
    q, err := hex.DecodeString(Qhex)
    if err!=nil{
        return nil, err
    }

    if len(q) == 65 && q[0] == byte(0x04) {
        q = q[1:]
    }

    if len(q) != 64 {
        return nil, errors.New("publicKey is not uncompressed.")
    }

    pub := new(PublicKey)
    pub.Curve = P256Sm2()
    pub.X = new(big.Int).SetBytes(q[:32])
    pub.Y = new(big.Int).SetBytes(q[32:])

    return pub, nil
}

// 输出公钥明文
func ToPublicKey(key *PublicKey) string {
    x := key.X.Bytes()
    y := key.Y.Bytes()
    if n := len(x); n < 32 {
        x = append(zeroByteSlice()[:32-n], x...)
    }

    if n := len(y); n < 32 {
        y = append(zeroByteSlice()[:32-n], y...)
    }

    c := []byte{}
    c = append(c, x...)
    c = append(c, y...)
    c = append([]byte{0x04}, c...)

    return hex.EncodeToString(c)
}

// sm2 密文结构: x + y + hash + CipherText
func Encrypt(random io.Reader, pub *PublicKey, data []byte, mode Mode) ([]byte, error) {
    length := len(data)
    for {
        c := []byte{}

        curve := pub.Curve

        k, err := randFieldElement(curve, random)
        if err != nil {
            return nil, err
        }

        x1, y1 := curve.ScalarBaseMult(k.Bytes())
        x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

        x1Buf := x1.Bytes()
        y1Buf := y1.Bytes()
        x2Buf := x2.Bytes()
        y2Buf := y2.Bytes()

        if n := len(x1Buf); n < 32 {
            x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
        }

        if n := len(y1Buf); n < 32 {
            y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
        }

        if n := len(x2Buf); n < 32 {
            x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
        }

        if n := len(y2Buf); n < 32 {
            y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
        }

        c = append(c, x1Buf...) // x分量
        c = append(c, y1Buf...) // y分量

        tm := []byte{}
        tm = append(tm, x2Buf...)
        tm = append(tm, data...)
        tm = append(tm, y2Buf...)

        h := sm3.Sum(tm)
        c = append(c, h[:]...)

        ct, ok := kdf(length, x2Buf, y2Buf) // 密文
        if !ok {
            continue
        }

        c = append(c, ct...)

        for i := 0; i < length; i++ {
            c[96+i] ^= data[i]
        }

        switch mode {
            case C1C3C2:
                return append([]byte{0x04}, c...), nil
            case C1C2C3:
                c1 := make([]byte, 64)
                c2 := make([]byte, len(c) - 96)
                c3 := make([]byte, 32)

                copy(c1, c[:64])   // x1, y1
                copy(c3, c[64:96]) // hash
                copy(c2, c[96:])   // 密文

                ciphertext := []byte{}
                ciphertext = append(ciphertext, c1...)
                ciphertext = append(ciphertext, c2...)
                ciphertext = append(ciphertext, c3...)

                return append([]byte{0x04}, ciphertext...), nil
            default:
                return append([]byte{0x04}, c...), nil
        }
    }
}

func Decrypt(priv *PrivateKey, data []byte, mode Mode) ([]byte, error) {
    switch mode {
        case C1C3C2:
            data = data[1:]
        case  C1C2C3:
            data = data[1:]
            c1 := make([]byte, 64)
            c2 := make([]byte, len(data) - 96)
            c3 := make([]byte, 32)

            copy(c1, data[:64])               // x1, y1
            copy(c2, data[64:len(data) - 32]) // 密文
            copy(c3, data[len(data) - 32:])   // hash

            c := []byte{}
            c = append(c, c1...)
            c = append(c, c3...)
            c = append(c, c2...)

            data = c
        default:
            data = data[1:]
    }

    length := len(data) - 96

    curve := priv.Curve

    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())

    x2Buf := x2.Bytes()
    y2Buf := y2.Bytes()

    if n := len(x2Buf); n < 32 {
        x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
    }

    if n := len(y2Buf); n < 32 {
        y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
    }

    c, ok := kdf(length, x2Buf, y2Buf)
    if !ok {
        return nil, errors.New("Decrypt: failed to decrypt")
    }

    for i := 0; i < length; i++ {
        c[i] ^= data[i+96]
    }

    tm := []byte{}
    tm = append(tm, x2Buf...)
    tm = append(tm, c...)
    tm = append(tm, y2Buf...)

    h := sm3.Sum(tm)

    if bytes.Compare(h[:], data[64:96]) != 0 {
        return c, errors.New("Decrypt: failed to decrypt")
    }

    return c, nil
}

// sm2 加密，返回 asn.1 编码格式的密文内容
func EncryptAsn1(rand io.Reader, pub *PublicKey, data []byte, mode Mode) ([]byte, error) {
    data, err := Encrypt(rand, pub, data, C1C3C2)
    if err != nil {
        return nil, err
    }

    if mode == C1C2C3 {
        return ASN1MarshalC1C2C3(data)
    }

    return ASN1Marshal(data)
}

// sm2解密，解析asn.1编码格式的密文内容
func DecryptAsn1(pub *PrivateKey, data []byte, mode Mode) ([]byte, error) {
    var err error

    if mode == C1C2C3 {
        data, err = ASN1UnmarshalC1C2C3(data)
        if err != nil {
            return nil, err
        }
    } else {
        data, err = ASN1Unmarshal(data)
        if err != nil {
            return nil, err
        }
    }

    return Decrypt(pub, data, C1C3C2)
}

func Sign(random io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
    e := new(big.Int).SetBytes(hash)
    c := priv.PublicKey.Curve

    N := c.Params().N
    if N.Sign() == 0 {
        return nil, nil, errZeroParam
    }

    var k *big.Int

    for {
        for {
            k, err = randFieldElement(c, random)
            if err != nil {
                r = nil
                return
            }

            r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
            r.Add(r, e)
            r.Mod(r, N)

            if r.Sign() != 0 {
                if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
                    break
                }
            }

        }

        rD := new(big.Int).Mul(priv.D, r)
        s = new(big.Int).Sub(k, rD)

        d1 := new(big.Int).Add(priv.D, one)
        d1Inv := new(big.Int).ModInverse(d1, N)

        s.Mul(s, d1Inv)
        s.Mod(s, N)

        if s.Sign() != 0 {
            break
        }
    }

    return
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
    c := pub.Curve
    N := c.Params().N

    if r.Sign() <= 0 || s.Sign() <= 0 {
        return false
    }

    if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
        return false
    }

    t := new(big.Int).Add(r, s)
    t.Mod(t, N)
    if t.Sign() == 0 {
        return false
    }

    var x *big.Int

    x1, y1 := c.ScalarBaseMult(s.Bytes())
    x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
    x, _ = c.Add(x1, y1, x2, y2)

    e := new(big.Int).SetBytes(hash)
    x.Add(x, e)
    x.Mod(x, N)

    return x.Cmp(r) == 0
}

func Sm2Sign(random io.Reader, priv *PrivateKey, msg, uid []byte) (r, s *big.Int, err error) {
    hash, err := sm3Digest(&priv.PublicKey, msg, uid)
    if err != nil {
        return nil, nil, err
    }

    return Sign(random, priv, hash)
}

func Sm2Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
    hash, err := sm3Digest(pub, msg, uid)
    if err != nil {
        return false
    }

    return Verify(pub, hash, r, s)
}

func sm3Digest(pub *PublicKey, msg, uid []byte) ([]byte, error) {
    if len(uid) == 0 {
        uid = defaultUid
    }

    za, err := ZA(pub, uid)
    if err != nil {
        return nil, err
    }

    e, err := msgHash(za, msg)
    if err != nil {
        return nil, err
    }

    return e.Bytes(), nil
}

func msgHash(za, msg []byte) (*big.Int, error) {
    e := sm3.New()

    e.Write(za)
    e.Write(msg)

    return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
    za := sm3.New()

    uidLen := len(uid)

    if uidLen >= 8192 {
        return []byte{}, errors.New("SM2: uid too large")
    }

    Entla := uint16(8 * uidLen)
    za.Write([]byte{byte((Entla >> 8) & 0xFF)})
    za.Write([]byte{byte(Entla & 0xFF)})

    if uidLen > 0 {
        za.Write(uid)
    }

    za.Write(sm2P256ToBig(&sm2P256.a).Bytes())
    za.Write(sm2P256.B.Bytes())
    za.Write(sm2P256.Gx.Bytes())
    za.Write(sm2P256.Gy.Bytes())

    xBuf := pub.X.Bytes()
    yBuf := pub.Y.Bytes()
    if n := len(xBuf); n < 32 {
        xBuf = append(zeroByteSlice()[:32-n], xBuf...)
    }

    if n := len(yBuf); n < 32 {
        yBuf = append(zeroByteSlice()[:32-n], yBuf...)
    }

    za.Write(xBuf)
    za.Write(yBuf)

    return za.Sum(nil)[:32], nil
}

type sm2ASN1 struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    HASH        []byte
    CipherText  []byte
}

// sm2 密文转 asn.1 编码格式
// sm2 密文结构: x + y + hash + CipherText
func ASN1Marshal(data []byte) ([]byte, error) {
    data = data[1:]

    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    hash := data[64:96]
    cipherText := data[96:]

    return asn1.Marshal(sm2ASN1{x, y, hash, cipherText})
}

// sm2 密文 asn.1 编码格式转 C1|C3|C2 拼接格式
func ASN1Unmarshal(b []byte) ([]byte, error) {
    var data sm2ASN1
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return nil, err
    }

    x := data.XCoordinate.Bytes()
    y := data.YCoordinate.Bytes()
    hash := data.HASH
    if err != nil {
        return nil, err
    }

    cipherText := data.CipherText
    if err != nil {
        return nil, err
    }

    if n := len(x); n < 32 {
        x = append(zeroByteSlice()[:32-n], x...)
    }

    if n := len(y); n < 32 {
        y = append(zeroByteSlice()[:32-n], y...)
    }

    c := []byte{}
    c = append(c, x...)          // x分量
    c = append(c, y...)          // y分
    c = append(c, hash...)       // hash
    c = append(c, cipherText...) // cipherText

    return append([]byte{0x04}, c...), nil
}

type sm2C1C2C3ASN1 struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    CipherText  []byte
    HASH        []byte
}

// sm2 密文转 asn.1 编码格式
// sm2 密文结构: x + y + hash + CipherText
func ASN1MarshalC1C2C3(data []byte) ([]byte, error) {
    data = data[1:]

    x := new(big.Int).SetBytes(data[:32])
    y := new(big.Int).SetBytes(data[32:64])

    hash := data[64:96]
    cipherText := data[96:]

    return asn1.Marshal(sm2C1C2C3ASN1{x, y, cipherText, hash})
}

// sm2 密文 asn.1 编码格式转 C1|C2|C3 拼接格式
func ASN1UnmarshalC1C2C3(b []byte) ([]byte, error) {
    var data sm2C1C2C3ASN1
    _, err := asn1.Unmarshal(b, &data)
    if err != nil {
        return nil, err
    }

    x := data.XCoordinate.Bytes()
    y := data.YCoordinate.Bytes()
    hash := data.HASH
    if err != nil {
        return nil, err
    }

    cipherText := data.CipherText
    if err != nil {
        return nil, err
    }

    if n := len(x); n < 32 {
        x = append(zeroByteSlice()[:32-n], x...)
    }

    if n := len(y); n < 32 {
        y = append(zeroByteSlice()[:32-n], y...)
    }

    c := []byte{}
    c = append(c, x...)          // x分量
    c = append(c, y...)          // y分
    c = append(c, hash...)       // hash
    c = append(c, cipherText...) // cipherText

    return append([]byte{0x04}, c...), nil
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
    if random == nil {
        random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
    }

    params := c.Params()

    b := make([]byte, params.BitSize/8+8)

    _, err = io.ReadFull(random, b)
    if err != nil {
        return
    }

    k = new(big.Int).SetBytes(b)
    n := new(big.Int).Sub(params.N, one)

    k.Mod(k, n)
    k.Add(k, one)

    return
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

// hex padding
func hexPadding(text string, size int) string {
    if size < 1 {
        return text
    }

    n := len(text)

    if n == size {
        return text
    }

    if n < size {
        return strings.Repeat("0", size-n) + text
    }

    return text[n-size:]
}
