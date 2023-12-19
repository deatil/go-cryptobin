package key

import (
    "errors"
    "reflect"
    "encoding/asn1"
    "crypto/elliptic"
    "crypto/x509/pkix"

    "github.com/tjfoc/gmsm/sm2"
)

var (
    oidSM2          = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
    oidPublicKeySM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// pkcs8
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

func ParsePKCS8PrivateKey(der []byte) (*sm2.PrivateKey, error) {
    var privKey pkcs8

    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, err
    }

    if !reflect.DeepEqual(privKey.Algo.Algorithm, oidSM2) {
        return nil, errors.New("x509: not sm2 elliptic curve")
    }

    return parseSM2PrivateKey(nil, privKey.PrivateKey)
}

func MarshalPKCS8PrivateKey(key *sm2.PrivateKey) ([]byte, error) {
    var r pkcs8
    var algo pkix.AlgorithmIdentifier

    oidBytes, err := asn1.Marshal(oidPublicKeySM2)
    if err != nil {
        return nil, errors.New("x509: failed to marshal algo param: " + err.Error())
    }

    algo.Algorithm = oidSM2
    algo.Parameters.Class = 0
    algo.Parameters.Tag = 6
    algo.Parameters.IsCompound = false
    algo.Parameters.FullBytes = oidBytes

    oid, ok := oidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("x509: unknown elliptic curve")
    }

    r.Version = 0
    r.Algo = algo
    r.PrivateKey, err = marshalSM2PrivateKeyWithOID(key, oid)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(r)
}

func ParsePublicKey(der []byte) (*sm2.PublicKey, error) {
    var pubkey pkixPublicKey

    if _, err := asn1.Unmarshal(der, &pubkey); err != nil {
        return nil, err
    }

    if !reflect.DeepEqual(pubkey.Algo.Algorithm, oidSM2) {
        return nil, errors.New("x509: not sm2 elliptic curve")
    }

    curve := sm2.P256Sm2()

    x, y := elliptic.Unmarshal(curve, pubkey.BitString.Bytes)

    pub := sm2.PublicKey{
        Curve: curve,
        X:     x,
        Y:     y,
    }

    return &pub, nil
}

func MarshalPublicKey(key *sm2.PublicKey) ([]byte, error) {
    var r pkixPublicKey
    var algo pkix.AlgorithmIdentifier

    if key.Curve.Params() != sm2.P256Sm2().Params() {
        return nil, errors.New("x509: unsupported elliptic curve")
    }

    oidBytes, err := asn1.Marshal(oidPublicKeySM2)
    if err != nil {
        return nil, errors.New("x509: failed to marshal algo param: " + err.Error())
    }

    algo.Algorithm = oidSM2
    algo.Parameters.Class = 0
    algo.Parameters.Tag = 6
    algo.Parameters.IsCompound = false
    algo.Parameters.FullBytes = oidBytes

    r.Algo = algo
    r.BitString = asn1.BitString{
        Bytes: elliptic.Marshal(key.Curve, key.X, key.Y),
    }

    return asn1.Marshal(r)
}
