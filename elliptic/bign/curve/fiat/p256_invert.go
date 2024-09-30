// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Code generated by addchain. DO NOT EDIT.
package fiat

// Invert sets e = 1/x, and returns e.
//
// If x == 0, Invert returns e = 0.
func (e *P256Element) Invert(x *P256Element) *P256Element {
    // Inversion is implemented as exponentiation with exponent p − 2.
    // The sequence of 13 multiplications and 255 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10       = 2*1
    //	_11       = 1 + _10
    //	_110      = 2*_11
    //	_111      = 1 + _110
    //	_1110     = 2*_111
    //	_1111     = 1 + _1110
    //	_1111000  = _1111 << 3
    //	_1111111  = _111 + _1111000
    //	_11111110 = 2*_1111111
    //	_11111111 = 1 + _11111110
    //	x15       = _11111111 << 7 + _1111111
    //	x16       = 2*x15 + 1
    //	x31       = x16 << 15 + x15
    //	x62       = x31 << 31 + x31
    //	x124      = x62 << 62 + x62
    //	x248      = x124 << 124 + x124
    //	return      (x248 << 2 + 1) << 6 + 1
    //
    var z = new(P256Element).Set(e)
    var t0 = new(P256Element)

    z.Square(x)
    z.Mul(x, z)
    z.Square(z)
    z.Mul(x, z)
    t0.Square(z)
    t0.Mul(x, t0)
    for s := 0; s < 3; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    t0.Square(z)
    t0.Mul(x, t0)
    for s := 0; s < 7; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    t0.Square(z)
    t0.Mul(x, t0)
    for s := 0; s < 15; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    t0.Square(z)
    for s := 1; s < 31; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    t0.Square(z)
    for s := 1; s < 62; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    t0.Square(z)
    for s := 1; s < 124; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    for s := 0; s < 2; s++ {
        z.Square(z)
    }
    z.Mul(x, z)
    for s := 0; s < 6; s++ {
        z.Square(z)
    }
    z.Mul(x, z)
    return e.Set(z)
}
