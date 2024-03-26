package hc

import (
    "strconv"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/hc: invalid key size " + strconv.Itoa(int(k))
}

type IVSizeError int

func (k IVSizeError) Error() string {
    return "cryptobin/hc: invalid iv size " + strconv.Itoa(int(k))
}
