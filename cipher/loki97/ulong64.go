package loki97

type ULONG64 struct {
    l uint64
    r uint64
}

func add64(a ULONG64, b ULONG64) ULONG64 {
    var sum ULONG64

    sum.r = a.r + b.r
    sum.l = a.l + b.l

    if sum.r < b.r {
        sum.l++
    }

    return sum
}

func sub64(a ULONG64, b ULONG64) ULONG64 {
    var diff ULONG64

    diff.r = a.r - b.r
    diff.l = a.l - b.l

    if diff.r > a.r {
        diff.l--
    }

    return diff
}

func byteToULONG64(inp []byte) ULONG64 {
    var I ULONG64

    I.l  = uint64(inp[0]) << 24
    I.l |= uint64(inp[1]) << 16
    I.l |= uint64(inp[2]) << 8
    I.l |= uint64(inp[3])

    I.r  = uint64(inp[4]) << 24
    I.r |= uint64(inp[5]) << 16
    I.r |= uint64(inp[6]) << 8
    I.r |= uint64(inp[7])

    return I
}

func ULONG64ToBYTE(I ULONG64) [8]byte {
    var sav [8]byte

    sav[0] = byte(I.l >> 24)
    sav[1] = byte(I.l >> 16)
    sav[2] = byte(I.l >> 8)
    sav[3] = byte(I.l)

    sav[4] = byte(I.r >> 24)
    sav[5] = byte(I.r >> 16)
    sav[6] = byte(I.r >> 8)
    sav[7] = byte(I.r)

    return sav
}
