package ed521

func (this ED521) OnError(fn func([]error)) ED521 {
    fn(this.Errors)

    return this
}

