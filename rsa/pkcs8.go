package rsa

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var oidPublicKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func ParsePKCS8PrivateKey(der []byte) (key *PrivateKey, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("go-cryptobin/rsa: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, err
	}

	if !privKey.Algo.Algorithm.Equal(oidPublicKeyRSA) {
		return nil, fmt.Errorf("go-cryptobin/rsa: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}

	key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("go-cryptobin/rsa: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
	}

	return key, nil
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
//
// MarshalPKCS8PrivateKey runs [PrivateKey.Precompute] on RSA keys.
func MarshalPKCS8PrivateKey(key *PrivateKey) ([]byte, error) {
	var privKey pkcs8

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm:  oidPublicKeyRSA,
		Parameters: asn1.NullRawValue,
	}
	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, err
	}

	privKey.PrivateKey = MarshalPKCS1PrivateKey(key)

	return asn1.Marshal(privKey)
}

// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form. The encoded
// public key is a SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func ParsePKIXPublicKey(derBytes []byte) (pub *PublicKey, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &pkcs1PublicKey{}); err == nil {
			return nil, errors.New("go-cryptobin/rsa: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("go-cryptobin/rsa: trailing data after ASN.1 of public-key")
	}

	return parsePublicKey(&pki)
}

// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func MarshalPKIXPublicKey(pub *PublicKey) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

func parsePublicKey(keyData *publicKeyInfo) (*PublicKey, error) {
	oid := keyData.Algorithm.Algorithm
	params := keyData.Algorithm.Parameters
	data := keyData.PublicKey.RightAlign()

	if !oid.Equal(oidPublicKeyRSA) {
		return nil, errors.New("go-cryptobin/rsa: unknown public key algorithm")
	}

	// RSA public keys must have a NULL in the parameters.
	// See RFC 3279, Section 2.3.1.
	if !bytes.Equal(params.FullBytes, asn1.NullBytes) {
		return nil, errors.New("go-cryptobin/rsa: RSA key missing NULL parameters")
	}

	der := cryptobyte.String(data)
	p := &pkcs1PublicKey{N: new(big.Int)}
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("go-cryptobin/rsa: invalid RSA public key")
	}
	if !der.ReadASN1Integer(p.N) {
		return nil, errors.New("go-cryptobin/rsa: invalid RSA modulus")
	}
	if !der.ReadASN1Integer(&p.E) {
		return nil, errors.New("go-cryptobin/rsa: invalid RSA public exponent")
	}

	if p.N.Sign() <= 0 {
		return nil, errors.New("go-cryptobin/rsa: RSA modulus is not a positive number")
	}
	if p.E <= 0 {
		return nil, errors.New("go-cryptobin/rsa: RSA public exponent is not a positive number")
	}

	pub := &PublicKey{
		E: p.E,
		N: p.N,
	}
	return pub, nil

}

func marshalPublicKey(pub *PublicKey) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
		N: pub.N,
		E: pub.E,
	})
	if err != nil {
		return nil, pkix.AlgorithmIdentifier{}, err
	}

	publicKeyAlgorithm.Algorithm = oidPublicKeyRSA

	// This is a NULL parameters value which is required by
	// RFC 3279, Section 2.3.1.
	publicKeyAlgorithm.Parameters = asn1.NullRawValue

	return publicKeyBytes, publicKeyAlgorithm, nil
}
