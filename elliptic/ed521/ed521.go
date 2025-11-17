package ed521

import (
    "sync"
    "encoding/asn1"
)

// see doc
// https://www.gov.br/iti/pt-br/assuntos/legislacao/documentos-principais/IN2022_22_DOC_ICP_01.01_assinado.pdf
// https://eprint.iacr.org/2013/647

var (
    // Ed-521 curve oid
    OIDED521 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44588, 2, 1}
)

var once sync.Once

func ED521() *Ed521Curve {
    once.Do(initAll)
    return ed521
}
