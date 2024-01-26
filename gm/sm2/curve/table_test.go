package curve

import (
    "fmt"
    "testing"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

func Test_lookupTable(t *testing.T) {
    var x, y, z field.Element
    var a, d PointJacobian
    var lt lookupTable

    x.SetBytes([]byte{0x11, 0x0, 0x80, 0x35, 0x0, 0x0, 0x0, 0x12, 0x01})
    y.SetBytes([]byte{0x10, 0x0, 0x81, 0x35, 0x0, 0x25, 0x0, 0x0, 0x01})
    z.SetBytes([]byte{0x10, 0x2, 0x81, 0x35, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x
    a.y = y
    a.z = z

    lt.Init(&a)
    lt.SelectInto(&d, 3)

    check := "9270d7fff7f6c7260969309f51dddbaa684ad0850539c0559e94959c213b182b-b00dc821359686adcbbf85ff0de78369e0bf30cba4bd523bc3faa88d3beec70c-cff4a65f79d4956dadd099d12e99316b29bc00f502f0d6ad5bf704c52add3443"
    got := fmt.Sprintf("%x-%x-%x", d.x.Bytes(), d.y.Bytes(), d.z.Bytes())

    if got != check {
        t.Errorf("lookupTable error, got %s, want %s", got, check)
    }
}

func Test_pointSelectInto(t *testing.T) {
    var a Point

    pointPrecomp(0).SelectInto(&a, 3)

    check := "82a0f5407d123db6cb129aa494da9ad4137f6c6149feef6ef81c8da9b99fba55-f12fa4696a22ca3fecacab94e973f9c3a961b58f0cf58373fdeca00772c4dbc9"
    got := fmt.Sprintf("%x-%x", a.x.Bytes(), a.y.Bytes())

    if got != check {
        t.Errorf("pointSelectInto error, got %s, want %s", got, check)
    }
}
