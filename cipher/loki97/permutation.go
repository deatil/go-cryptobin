package loki97

// 256
const PERMUTATION_SIZE = 0x100

func permutationGeneration() [PERMUTATION_SIZE]ULONG64 {
    var P [PERMUTATION_SIZE]ULONG64

    var pval uint32
    var i int16

    var j, k int16

    for i = 0; i < PERMUTATION_SIZE; i++ {
        pval = 0
        for j, k = 0, 7; j < 4; j, k = j+1, k+8 {
            pval |= uint32(((i >> j) & 0x1)) << k
        }
        P[i].r = pval

        pval = 0
        for j, k = 4, 7; j < 8; j, k = j+1, k+8 {
            pval |= uint32(((i >> j) & 0x1)) << k
        }
        P[i].l = pval
    }

    return P
}

// func f
func compute(A ULONG64, B ULONG64) ULONG64 {
    var d, e, f ULONG64

    d.l = ((A.l & ^B.r) | (A.r & B.r))
    d.r = ((A.r & ^B.r) | (A.l & B.r))

    // Compute e = P(Sa(d))
    //    mask out each group of 12 bits for E
    //    then compute first S-box column [S1,S2,S1,S2,S2,S1,S2,S1]
    //    permuting output through P (with extra shift to build full P)

    var s int16

    s = int16(S1[int16((d.l >> 24 | d.r << 8) & 0x1FFF)])
    e.l = P[s].l >> 7
    e.r = P[s].r >> 7

    s = int16(S1[int16((d.l >> 16) & 0x7FF)])
    e.l |= P[s].l >> 6
    e.r |= P[s].r >> 6

    s = int16(S1[int16((d.l >> 8) & 0x1FFF)])
    e.l |= P[s].l >> 5
    e.r |= P[s].r >> 5

    s = int16(S1[int16(d.l & 0x7FF)])
    e.l |= P[s].l >> 4
    e.r |= P[s].r >> 4

    s = int16(S1[int16((d.r >> 24 | d.l << 8) & 0x7FF)])
    e.l |= P[s].l >> 3
    e.r |= P[s].r >> 3

    s = int16(S1[int16((d.r >> 16) & 0x1FFF)])
    e.l |= P[s].l >> 2
    e.r |= P[s].r >> 2

    s = int16(S1[int16((d.r >> 8) & 0x7FF)])
    e.l |= P[s].l >> 1
    e.r |= P[s].r >> 1

    s = int16(S1[int16(d.r & 0x1FFF)])
    e.l |= P[s].l
    e.r |= P[s].r

    // Compute f = Sb(e,B)
    //    where the second S-box column is [S2,S2,S1,S1,S2,S2,S1,S1]
    //    for each S, lower bits come from e, upper from upper half of B

    f.l = uint32(
          (S2[int16(((e.l >> 24) & 0xFF) | ((B.l >> 21) &  0x700))]) << 24 |
          (S2[int16(((e.l >> 16) & 0xFF) | ((B.l >> 18) &  0x700))]) << 16 |
          (S1[int16(((e.l >>  8) & 0xFF) | ((B.l >> 13) & 0x1F00))]) <<  8 |
          (S1[int16(((e.l      ) & 0xFF) | ((B.l >>  8) & 0x1F00))]))

    f.r = uint32(
          (S2[int16(((e.r >> 24) & 0xFF) | ((B.l >> 5) &  0x700))]) << 24 |
          (S2[int16(((e.r >> 16) & 0xFF) | ((B.l >> 2) &  0x700))]) << 16 |
          (S1[int16(((e.r >>  8) & 0xFF) | ((B.l << 3) & 0x1F00))]) <<  8 |
          (S1[int16(( e.r        & 0xFF) | ((B.r << 8) & 0x1F00))]))

    return f
}
