package dsa

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// append error
func (this DSA) AppendError(err ...error) DSA {
    this.Errors = append(this.Errors, err...)

    return this
}

// return error
func (this DSA) Error() error {
    return errors.Join(this.Errors...)
}
