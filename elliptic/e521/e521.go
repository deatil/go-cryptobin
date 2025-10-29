package e521

import (
    "sync"
    "encoding/asn1"
)

// Implements support for ECC over Curve E-521 as specified in the
// Brazilian national cryptographic standards defined in:
//
//   ITI DOC-ICP-01.01 — Brazilian Cryptographic Standards for Public-Key Algorithms
//
// This standard is maintained under the ICP-Brasil framework by the
// Instituto Nacional de Tecnologia da Informação (ITI) and mandates the
// use of secure, internationally reviewed algorithms for digital
// certificates and electronic signatures.
//
// Curve E-521 is a high-security elliptic curve consistent with 512-bit
// security strength and is considered future-safe for use in digital
// signatures and key agreement protocols.
//
// Officially approved via:
//   - Instrução Normativa ITI nº 22, de 23 de março de 2022
//
// References:
//   - ICP-Brasil – DOC-ICP-01.01, v5.0 (2022)
//     https://www.gov.br/iti/pt-br/assuntos/legislacao/documentos-principais/IN2022_22_DOC_ICP_01.01_assinado.pdf
//   - Instrução Normativa ITI nº 22/2022 – Instituto Nacional de Tecnologia da Informação
//   - Diego F. Aranha, Paulo S. L. M. Barreto, Geovandro C. C. F. Pereira, Jefferson Ricardini,
//     "A note on high-security general-purpose elliptic curves", 2013.
//     https://eprint.iacr.org/2013/647
//
// This code implements PureEdDSA using SHAKE256 over the E-521 Edwards curve,
// compliant with the above specifications.

var (
    // E-521 EdDSA curve oid
    OIDE521 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44588, 2, 1}
)

var once sync.Once

func E521() *E521Curve {
    once.Do(initAll)
    return e521
}
