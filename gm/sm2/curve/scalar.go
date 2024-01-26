package curve

import (
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

// init scalar list data
var scalars [9]field.Element

func init() {
    for i, _ := range scalars {
        scalar := new(big.Int).SetBytes([]byte{byte(i)})

        scalars[i].SetBytes(scalar.Bytes())
    }
}
