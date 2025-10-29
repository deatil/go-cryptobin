package e521

import (
    "testing"
    "crypto/elliptic"
)

func Test_Interface(t *testing.T) {
    var _ elliptic.Curve = (*E521Curve)(nil)
}
