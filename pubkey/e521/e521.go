package e521

import (
    "io"
    "errors"
    "math/big"
    "crypto"
    "crypto/subtle"
    "crypto/elliptic"

    "golang.org/x/crypto/sha3"

    "github.com/deatil/go-cryptobin/elliptic/e521"
)

var (
    one = big.NewInt(1)
)

type PublicKey struct {
    elliptic.Curve

    X, Y *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.X.Cmp(xx.X) == 0 &&
        pub.Y.Cmp(xx.Y) == 0 &&
        pub.Curve == xx.Curve
}

// Verify verifies the signature of message for a given public key
func (pub *PublicKey) Verify(message, sig []byte) bool {
    curve := pub.Curve

    N := curve.Params().N
    byteLen := (curve.Params().BitSize + 7) / 8

    if len(sig) != byteLen*2 {
        return false
    }

    RCompressed := sig[:byteLen]
    sBytes := sig[byteLen:]

    Rx, Ry := e521.UnmarshalCompressed(curve, RCompressed)
    if Rx == nil || Ry == nil {
        return false
    }

    s := bytesToLittleInt(sBytes)
    if s.Cmp(N) >= 0 {
        return false
    }

    ACompressed := e521.MarshalCompressed(curve, pub.X, pub.Y)

    // Compute h = SHAKE256(dom || R || A || message) mod N
    hramInput := append(append(RCompressed, ACompressed...), message...)
    hramHash := hashE521(0x00, []byte{}, hramInput)
    hram := bytesToLittleInt(hramHash[:byteLen])
    hram.Mod(hram, N)

    // Compute s*G
    sGx, sGy := curve.ScalarBaseMult(littleIntToBytes(s, byteLen))

    // Compute h*A
    hAx, hAy := curve.ScalarMult(pub.X, pub.Y, littleIntToBytes(hram, byteLen))

    // Compute R + h*A
    rhaX, rhaY := curve.Add(Rx, Ry, hAx, hAy)

    // Constant time comparison
    return constantTimeEqual(sGx, rhaX) && constantTimeEqual(sGy, rhaY)
}

type PrivateKey struct {
    PublicKey

    D *big.Int
}

// GetPublic retorna a chave pública associada
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

// Sign creates a signature for message
func (priv *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
    curve := priv.Curve

    N := curve.Params().N
    byteLen := (curve.Params().BitSize + 7) / 8

    // 1. Hash prefix "dom" + priv.D bytes
    prefix := hashE521(0x00, []byte{}, littleIntToBytes(priv.D, byteLen))

    // 2. Calculate r = SHAKE256(prefix || message) mod N
    rBytes := hashE521(0x00, []byte{}, append(prefix, message...))
    r := bytesToLittleInt(rBytes[:byteLen])
    r.Mod(r, N)

    // 3. Compute R = r*G and compress
    Rx, Ry := curve.ScalarBaseMult(littleIntToBytes(r, byteLen))
    RCompressed := e521.MarshalCompressed(curve, Rx, Ry)

    // 4. Compress public key A
    ACompressed := e521.MarshalCompressed(curve, priv.X, priv.Y)

    // 5. Compute h = SHAKE256(dom || R || A || message) mod N
    hramInput := append(append(RCompressed, ACompressed...), message...)
    hramHash := hashE521(0x00, []byte{}, hramInput)
    hram := bytesToLittleInt(hramHash[:byteLen])
    hram.Mod(hram, N)

    // 6. s = (r + h * a) mod N
    s := new(big.Int).Mul(hram, priv.D)
    s.Add(s, r)
    s.Mod(s, N)

    // 7. Signature = RCompressed || sBytes
    sBytes := littleIntToBytes(s, byteLen)
    signature := append(RCompressed, sBytes...)

    return signature, nil
}

// GenerateKey returns E-521 EdDSA PrivateKey
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
    curve := e521.E521()

    k, err := randFieldElement(rand, curve)
    if err != nil {
        return nil, err
    }

    // A = a * G
    x, y := curve.ScalarBaseMult(littleIntToBytes(k, (curve.Params().BitSize+7)/8))

    return &PrivateKey{
        PublicKey: PublicKey{
            X: x,
            Y: y,
            Curve: curve,
        },
        D: k,
    }, nil
}

// New a private key from key data bytes
func NewPrivateKey(d []byte) (*PrivateKey, error) {
    curve := e521.E521()

    k := new(big.Int).SetBytes(d)

    n := new(big.Int).Sub(curve.Params().N, one)
    if k.Cmp(n) >= 0 {
        return nil, errors.New("go-cryptobin/e521: privateKey's D is overflow")
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(littleIntToBytes(k, (curve.Params().BitSize+7)/8))

    return priv, nil
}

// return PrivateKey data
func PrivateKeyTo(key *PrivateKey) []byte {
    privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
    return key.D.FillBytes(privateKey)
}

// New a PublicKey from publicKey data
func NewPublicKey(data []byte) (*PublicKey, error) {
    curve := e521.E521()

    x, y := e521.Unmarshal(curve, data)
    if x == nil || y == nil {
        return nil, errors.New("go-cryptobin/e521: incorrect public key")
    }

    pub := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    return pub, nil
}

// return PublicKey data
func PublicKeyTo(key *PublicKey) []byte {
    return e521.Marshal(key.Curve, key.X, key.Y)
}

// sign data and return marshal plain data
func Sign(rand io.Reader, priv *PrivateKey, msg []byte) ([]byte, error) {
    if priv == nil {
        return nil, errors.New("go-cryptobin/e521: invalid private key")
    }

    return priv.Sign(rand, msg, nil)
}

// Verify marshaled plain data
func Verify(pub *PublicKey, msg, signature []byte) (bool, error) {
    if pub == nil {
        return false, errors.New("go-cryptobin/e521: invalid public key")
    }

    return pub.Verify(msg, signature), nil
}

func randFieldElement(rand io.Reader, curve elliptic.Curve) (*big.Int, error) {
    N := curve.Params().N

    byteLen := (N.BitLen() + 7) / 8
    bytes := make([]byte, byteLen)

    for {
        _, err := io.ReadFull(rand, bytes)
        if err != nil {
            return nil, err
        }

        num := bytesToLittleInt(bytes)
        if num.Cmp(N) < 0 {
            return num, nil
        }
    }
}

// dom5
func dom5(phflag byte, context []byte) []byte {
    if len(context) > 255 {
        panic("context too long for dom5")
    }

    dom := []byte("SigEd521")
    dom = append(dom, phflag)
    dom = append(dom, byte(len(context)))
    dom = append(dom, context...)
    return dom
}

// hashE521 implementa H(x) = SHAKE256(dom5(phflag,context)||x, 132)
func hashE521(phflag byte, context, x []byte) []byte {
    dom := dom5(phflag, context)

    h := sha3.NewShake256()
    h.Write(dom)
    h.Write(x)

    // Output 132 bytes
    hash := make([]byte, 132)
    h.Read(hash)
    return hash
}

// bytesToLittleInt converte bytes little-endian to big.Int
func bytesToLittleInt(b []byte) *big.Int {
    reversed := make([]byte, len(b))
    for i := 0; i < len(b); i++ {
        reversed[i] = b[len(b)-1-i]
    }

    return new(big.Int).SetBytes(reversed)
}

// littleIntToBytes converte big.Int to bytes little-endian
func littleIntToBytes(n *big.Int, length int) []byte {
    bytes := n.Bytes()

    if len(bytes) < length {
        padding := make([]byte, length-len(bytes))
        bytes = append(padding, bytes...)
    }

    reversed := make([]byte, length)
    for i := 0; i < length; i++ {
        reversed[i] = bytes[length-1-i]
    }

    return reversed
}

func constantTimeEqual(a, b *big.Int) bool {
    if a == nil || b == nil {
        return false
    }

    aBytes := a.Bytes()
    bBytes := b.Bytes()

    maxLen := len(aBytes)
    if len(bBytes) > maxLen {
        maxLen = len(bBytes)
    }

    aPadded := make([]byte, maxLen)
    bPadded := make([]byte, maxLen)

    copy(aPadded[maxLen-len(aBytes):], aBytes)
    copy(bPadded[maxLen-len(bBytes):], bBytes)

    return subtle.ConstantTimeCompare(aPadded, bPadded) == 1
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
