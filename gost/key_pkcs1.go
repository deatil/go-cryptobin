package gost

import (
    "fmt"
    "errors"
    "encoding/asn1"
)

// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type gostPrivateKey struct {
    Version       int
    PrivateKey    []byte
    NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
    PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// pkcs1
func ParseGostPrivateKey(der []byte) (*PrivateKey, error) {
    return parseGostPrivateKey(nil, der)
}

// pkcs1
func MarshalGostPrivateKey(key *PrivateKey) ([]byte, error) {
    oid, ok := OidFromNamedCurve(key.Curve)
    if !ok {
        return nil, errors.New("x509: unknown elliptic curve")
    }

    return marshalGostPrivateKeyWithOID(key, oid)
}

func marshalGostPrivateKeyWithOID(key *PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
    if !key.Curve.IsOnCurve(key.X, key.Y) {
        return nil, errors.New("invalid gost key public key")
    }

    privateKey := make([]byte, key.Curve.PointSize())

    return asn1.Marshal(gostPrivateKey{
        Version:       gostPrivKeyVersion,
        PrivateKey:    key.D.FillBytes(privateKey),
        NamedCurveOID: oid,
        PublicKey:     asn1.BitString{
            Bytes: Marshal(key.Curve, key.X, key.Y),
        },
    })
}

func parseGostPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *PrivateKey, err error) {
    var privKey gostPrivateKey
    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, errors.New("gost: failed to parse EC private key: " + err.Error())
    }

    if privKey.Version != gostPrivKeyVersion {
        return nil, fmt.Errorf("gost: unknown EC private key version %d", privKey.Version)
    }

    var curve *Curve
    if namedCurveOID != nil {
        curve = NamedCurveFromOid(*namedCurveOID)
    } else {
        curve = NamedCurveFromOid(privKey.NamedCurveOID)
    }

    if curve == nil {
        return nil, errors.New("gost: unknown gost curve")
    }

    priv, err := NewPrivateKey(curve, privKey.PrivateKey)
    if err != nil {
        return nil, err
    }

    return priv, nil
}
