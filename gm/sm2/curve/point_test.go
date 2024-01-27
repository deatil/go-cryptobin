package curve

import (
    "fmt"
    "testing"
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

func Test_Point_Double(t *testing.T) {
    var x, y, z field.Element
    var a, d PointJacobian

    x.SetBytes([]byte{0x11, 0x0, 0x18, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y.SetBytes([]byte{0x10, 0x0, 0x18, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z.SetBytes([]byte{0x10, 0x2, 0x18, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x
    a.y = y
    a.z = z

    d.Double(&a)

    check := "8bcb5b6a434cec0b5d823a8bab88df350dc79944d864635469c8ce64f4a69e45-04772b6865006771085483892856a0651336c0ca33219010cab3bb09f97ba1fd-0200460ca55fb363fc940f12c40094000002"
    got := fmt.Sprintf("%x-%x-%x", d.x.Bytes(), d.y.Bytes(), d.z.Bytes())

    if got != check {
        t.Errorf("Double error, got %s, want %s", got, check)
    }
}

func Test_Point_Sub(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b, d PointJacobian

    x1.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetBytes([]byte{0x11, 0x5, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x1, 0x25, 0x0, 0x0, 0x01})
    z2.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x26, 0x0, 0x1, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    d.Sub(&a, &b)

    check := "70e5f254c205a5acec04ecdd547738959d1f7bf9af940c75c0f22ef138e93851-4bbeabe518f2054a85989c1427249d8f24a6a3ce782d53efae3fc5007e00979a-8b1ec36a55a675a8efb72a817082fc86b649a3b6b76bbf6368c89f7bd108144e"
    got := fmt.Sprintf("%x-%x-%x", d.x.Bytes(), d.y.Bytes(), d.z.Bytes())

    if got != check {
        t.Errorf("Sub error, got %s, want %s", got, check)
    }
}

func Test_Point_Add(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b, d PointJacobian

    x1.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetBytes([]byte{0x11, 0x5, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x1, 0x25, 0x0, 0x0, 0x01})
    z2.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x26, 0x0, 0x1, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    d.Add(&a, &b)

    check := "42d4656134e2781030ce2f5c655eeb08b0cefe1704111c752434c7ee022b04d8-867ac44ba07216236562e15073f60d8a010dab7fca09c7fa44b0928d3c1a2c66-8b1ec36a55a675a8efb72a817082fc86b649a3b6b76bbf6368c89f7bd108144e"
    got := fmt.Sprintf("%x-%x-%x", d.x.Bytes(), d.y.Bytes(), d.z.Bytes())

    if got != check {
        t.Errorf("Add error, got %s, want %s", got, check)
    }
}

func Test_Point_ToBig(t *testing.T) {
    var x1, y1, z1 field.Element
    var a PointJacobian
    var aa Point

    x1.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    x, y := new(big.Int), new(big.Int)
    aa.FromJacobian(&a).ToBig(x, y)

    check := "2c2a81f92dd211a5a7785019dac28696edc709eea8615a73e1f2d43bb4e5d4c2-5f6a4b9cf87581fa90b41e61a3f183a0813fa7aafb35a72fa8e0cae0d5e3e26e"
    got := fmt.Sprintf("%x-%x", x.Bytes(), y.Bytes())

    if got != check {
        t.Errorf("ToBig error, got %s, want %s", got, check)
    }
}

func Test_Point_AddMixed(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2 field.Element
    var a, d PointJacobian
    var b Point

    x1.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetBytes([]byte{0x15, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetBytes([]byte{0x16, 0x1, 0x12, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2

    d.AddMixed(&a, &b)

    check := "d7805bf2be758e01e1b36b1199c4cf4ab55821ff0a13d67b9012d5a905abc255-1711bd87c6866c3e5019ad3d9eef69b18795e0a7216e0773cfe0ff272b95bc11-d531dd00387643ff321fe0ac93ba31f31bc2aee8dc3f81430be2ce689402a14b"
    got := fmt.Sprintf("%x-%x-%x", d.x.Bytes(), d.y.Bytes(), d.z.Bytes())

    if got != check {
        t.Errorf("AddMixed error, got %s, want %s", got, check)
    }
}

func Test_Point_ScalarBaseMult(t *testing.T) {
    var d PointJacobian
    var scalar [32]uint8

    scalar = [32]uint8{
        1, 2, 3, 4, 5, 6, 7, 8,
        21, 22, 23, 24, 25, 26, 27, 28,
        31, 32, 33, 34, 35, 36, 37, 38,
        11, 12, 13, 14, 15, 16, 17, 18,
    }

    d.ScalarBaseMult(scalar[:])

    check := "25bc8c3ff69ab40b0858fb149598a9b9285aeab91f5ba8d9fb748188f8396cd0-a08b1711e4fcdc4a4a4dde6ac211ab9e543751a78d453c66ff06a363bef971cb-3b97792c735eb1cfe8a59d4f6dc189cfafb2cc261fb039478e37ac1f67607e6d"
    got := fmt.Sprintf("%x-%x-%x", d.x.Bytes(), d.y.Bytes(), d.z.Bytes())

    if got != check {
        t.Errorf("ScalarBaseMult error, got %s, want %s", got, check)
    }
}

func Test_Point_ScalarMult(t *testing.T) {
    var x1, y1 field.Element
    var d, ad PointJacobian
    var a Point
    var scalar []byte

    x1.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    x := new(big.Int).SetBytes(x1.Bytes())
    y := new(big.Int).SetBytes(y1.Bytes())

    a.NewPoint(x, y)

    scalar = []byte{
        1, 2, 3, 4, 5, 6, 7, 8,
        3, 4, 5, 6, 11, 12, 13, 14,
        1, 2, 3, 4, 5, 6, 7, 8,
        11, 12, 13, 14, 15, 6, 7, 8,
    }

    ad.FromAffine(&a)

    d.ScalarMult(&ad, scalar)

    check := "5d5db11b93118d0afa08a9ea64a89c53805cafa6af1b48894f02bd3bd8b3b03a-b092d0a6cd7655a9497840759e65268949631bfbaae9b8db09fe0b838036f74e-f11c14c6fc6c5c0aa838d7b26384e0d0e071b08e9fa4ce3d6c3fbab8fd25d8ec"
    got := fmt.Sprintf("%x-%x-%x", d.x.Bytes(), d.y.Bytes(), d.z.Bytes())

    if got != check {
        t.Errorf("ScalarMult error, got %s, want %s", got, check)
    }
}

func Test_Point_Equal(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b PointJacobian

    x1.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z2.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    eq := a.Equal(&b)
    if eq != 1 {
        t.Errorf("Equal error, got %d", eq)
    }
}

func Test_Point_NotEqual(t *testing.T) {
    var x1, y1, z1 field.Element
    var x2, y2, z2 field.Element
    var a, b PointJacobian

    x1.SetBytes([]byte{0x11, 0x0, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y1.SetBytes([]byte{0x10, 0x0, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z1.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    x2.SetBytes([]byte{0x11, 0x1, 0x80, 0x31, 0x0, 0x0, 0x0, 0x12, 0x01})
    y2.SetBytes([]byte{0x10, 0x0, 0x31, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})
    z2.SetBytes([]byte{0x10, 0x2, 0x81, 0x31, 0x0, 0x25, 0x0, 0x0, 0x01})

    a.x = x1
    a.y = y1
    a.z = z1

    b.x = x2
    b.y = y2
    b.z = z2

    eq := a.Equal(&b)
    if eq == 1 {
        t.Errorf("NotEqual error, got %d", eq)
    }
}

func Test_Point_NewGenerator(t *testing.T) {
    var a Point

    a.NewGenerator()

    check := "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7-bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
    got := fmt.Sprintf("%x-%x", a.x.Bytes(), a.y.Bytes())

    if got != check {
        t.Errorf("NewGenerator error, got %s, want %s", got, check)
    }
}
