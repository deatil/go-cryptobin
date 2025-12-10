package ecdh

func (this ECDH) OnError(fn func([]error)) ECDH {
    fn(this.Errors)

    return this
}

