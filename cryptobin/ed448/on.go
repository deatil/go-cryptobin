package ed448

func (this ED448) OnError(fn func([]error)) ED448 {
    fn(this.Errors)

    return this
}

