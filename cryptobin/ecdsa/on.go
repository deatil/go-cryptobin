package ecdsa

func (this ECDSA) OnError(fn func([]error)) ECDSA {
    fn(this.Errors)

    return this
}

