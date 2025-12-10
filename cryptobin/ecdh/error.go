package ecdh

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// append error
func (this ECDH) AppendError(err ...error) ECDH {
    this.Errors = append(this.Errors, err...)

    return this
}

// return error
func (this ECDH) Error() error {
    return errors.Join(this.Errors...)
}
