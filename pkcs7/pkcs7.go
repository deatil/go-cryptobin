package pkcs7

import (
    "fmt"
    "sort"
    "errors"
    "bytes"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/ber"
)

var (
    // Signed Data OIDs
    oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
    oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
    oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
    OIDSignedEnvelopedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
    OIDDigestData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
    oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
    oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
    oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
    oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

var (
    // SM2 Signed Data OIDs
    OidSM2Data                = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
    OidSM2SignedData          = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
    OidSM2EnvelopedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 3}
    OidSM2SignedEnvelopedData = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 4}
    OidSM2EncryptedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 5}

    // Digest Algorithms
    // OidDigestAlgorithmSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
    // SM2Sign-with-SM3
    OidDigestAlgorithmSM2SM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
    // Signature Algorithms SM2-1
    OidDigestEncryptionAlgorithmSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}

    // Encryption Algorithms SM2-3
    OidKeyEncryptionAlgorithmSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}

    // SM9 Signed Data OIDs
    OidSM9Data                = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 1}
    OidSM9SignedData          = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 2}
    OidSM9EnvelopedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 3}
    OidSM9SignedEnvelopedData = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 4}
    OidSM9EncryptedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 5}

    // SM9Sign-with-SM3
    OidDigestAlgorithmSM9SM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}

    // Signature Algorithms SM9-1
    OidDigestEncryptionAlgorithmSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 1}

    // Encryption Algorithms SM9-3
    OidKeyEncryptionAlgorithmSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 3}
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
    Content      []byte
    Certificates []*x509.Certificate
    CRLs         []pkix.CertificateList
    Signers      []signerInfo
    raw          interface{}
}

type contentInfo struct {
    ContentType asn1.ObjectIdentifier
    Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.840.113549.1.7.1), Signed Data (1.2.840.113549.1.7.2),
// and Enveloped Data are supported (1.2.840.113549.1.7.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

// Parse decodes a DER encoded PKCS7 package
func Parse(data []byte) (p7 *PKCS7, err error) {
    if len(data) == 0 {
        return nil, errors.New("pkcs7: input data is empty")
    }

    var info contentInfo
    der, err := ber.Ber2der(data)
    if err != nil {
        return nil, err
    }

    rest, err := asn1.Unmarshal(der, &info)
    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    if err != nil {
        return
    }

    switch {
        case info.ContentType.Equal(oidSignedData):
            return parseSignedData(info.Content.Bytes)
    }

    return nil, ErrUnsupportedContentType
}

func (raw rawCertificates) Parse() ([]*x509.Certificate, error) {
    if len(raw.Raw) == 0 {
        return nil, nil
    }

    var val asn1.RawValue
    if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
        return nil, err
    }

    return x509.ParseCertificates(val.Bytes)
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
    Type  asn1.ObjectIdentifier
    Value interface{}
}

type attributes struct {
    types  []asn1.ObjectIdentifier
    values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
    attrs.types = append(attrs.types, attrType)
    attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
    SortKey   []byte
    Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
    return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
    return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
    sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
    attrs := make([]attribute, len(sa))
    for i, attr := range sa {
        attrs[i] = attr.Attribute
    }
    return attrs
}

func (attrs *attributes) ForMarshalling() ([]attribute, error) {
    sortables := make(attributeSet, len(attrs.types))
    for i := range sortables {
        attrType := attrs.types[i]
        attrValue := attrs.values[i]

        asn1Value, err := asn1.Marshal(attrValue)
        if err != nil {
            return nil, err
        }

        attr := attribute{
            Type:  attrType,
            Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
        }

        encoded, err := asn1.Marshal(attr)
        if err != nil {
            return nil, err
        }

        sortables[i] = sortableAttribute{
            SortKey:   encoded,
            Attribute: attr,
        }
    }

    sort.Sort(sortables)
    return sortables.Attributes(), nil
}

func parseSignFromOid(signOid asn1.ObjectIdentifier) (KeySign, error) {
    oid := signOid.String()
    signFunc, ok := keySigns[oid]
    if !ok {
        return nil, fmt.Errorf("pkcs7: unsupported signHash (OID: %s)", oid)
    }

    newSignFunc := signFunc()
    return newSignFunc, nil
}

func parseSignFromHashOid(hashOid asn1.ObjectIdentifier) (KeySign, error) {
    for _, signFunc := range keySigns {
        newSignFunc := signFunc()
        if newSignFunc.HashOID().Equal(hashOid) {
            return newSignFunc, nil
        }
    }

    return nil, fmt.Errorf("pkcs7: unsupported signHash from hash (OID: %s)", hashOid.String())
}

func parseHashFromOid(hashOid asn1.ObjectIdentifier) (SignHash, error) {
    oid := hashOid.String()
    hashFunc, ok := signHashs[oid]
    if !ok {
        return nil, fmt.Errorf("pkcs7: unsupported signHash (OID: %s)", oid)
    }

    newHashFunc := hashFunc()
    return newHashFunc, nil
}
