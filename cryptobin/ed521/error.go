package ed521

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// append error
func (this ED521) AppendError(err ...error) ED521 {
    this.Errors = append(this.Errors, err...)

    return this
}

// return error
func (this ED521) Error() error {
    return errors.Join(this.Errors...)
}
