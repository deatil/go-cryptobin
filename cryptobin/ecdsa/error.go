package ecdsa

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// append error
func (this ECDSA) AppendError(err ...error) ECDSA {
    this.Errors = append(this.Errors, err...)

    return this
}

// return error
func (this ECDSA) Error() error {
    return errors.Join(this.Errors...)
}
