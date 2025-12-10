package ed448

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// append error
func (this ED448) AppendError(err ...error) ED448 {
    this.Errors = append(this.Errors, err...)

    return this
}

// return error
func (this ED448) Error() error {
    return errors.Join(this.Errors...)
}
