package ca

import (
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/x509"
)

// pkix
type (
    // Subject 数据
    PkixName = pkix.Name

    // Extension
    PkixExtension = pkix.Extension

    // CertificateList
    PkixCertificateList = pkix.CertificateList

    // RevokedCertificate
    PkixRevokedCertificate = pkix.RevokedCertificate

    // TBSCertificateList
    PkixTBSCertificateList = pkix.TBSCertificateList

    // RDNSequence
    PkixRDNSequence = pkix.RDNSequence

    // AttributeTypeAndValue 数据
    PkixAttributeTypeAndValue = pkix.AttributeTypeAndValue

    // AlgorithmIdentifier
    PkixAlgorithmIdentifier = pkix.AlgorithmIdentifier

    // AttributeTypeAndValueSET
    PkixAttributeTypeAndValueSET = pkix.AttributeTypeAndValueSET
)

// x905
type (
    // 证书
    Certificate = x509.Certificate

    // 证书请求
    CertificateRequest = x509.CertificateRequest

    // 配置别名
    VerifyOptions = x509.VerifyOptions

    // KeyUsage
    KeyUsage = x509.KeyUsage

    // ExtKeyUsage
    ExtKeyUsage = x509.ExtKeyUsage

    // SignatureAlgorithm
    SignatureAlgorithm = x509.SignatureAlgorithm

    // PublicKeyAlgorithm
    PublicKeyAlgorithm = x509.PublicKeyAlgorithm
)
