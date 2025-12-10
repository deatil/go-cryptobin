package dsa

func (this DSA) OnError(fn func([]error)) DSA {
    fn(this.Errors)

    return this
}

