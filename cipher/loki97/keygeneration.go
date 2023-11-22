package loki97

const NUM_SUBKEYS = 48
var DELTA = ULONG64{0x9E3779B9, 0x7F4A7C15}

func makeKey(k []byte) [NUM_SUBKEYS]ULONG64 {
    var SK [NUM_SUBKEYS]ULONG64   // array of subkeys

    var deltan ULONG64 = DELTA  // multiples of delta

    var i int32 = 0             // index into key input
    var k4, k3, k2, k1 ULONG64  // key schedule 128-bit entities
    var f_out ULONG64           // fn f output value for debug
    var t1, t2 ULONG64

    var tmp uint64

    tmp = 0
    for i = 0; i < 8; i++ {
        tmp = (tmp << 8)
        tmp |= uint64(k[i])
    }

    // pack key into 128-bit entities: k4, k3, k2, k1
    k4.l = tmp >> 32
    k4.r = tmp

    tmp = 0
    for i = 8; i < 16; i++ {
        tmp = (tmp << 8)
        tmp |= uint64(k[i])
    }

    k3.l = tmp >> 32
    k3.r = tmp

    if (len(k) == 16) {
        // 128-bit key - call fn f twice to gen 256 bits
        k2 = compute(k3, k4)
        k1 = compute(k4, k3)
    } else {
        tmp = 0
        for i = 16; i < 24; i++ {
            tmp = (tmp << 8)
            tmp |= uint64(k[i])
        }

        // 192 or 256-bit key - pack k2 from key data
        k2.l = tmp >> 32
        k2.r = tmp

        if (len(k) == 24) {
            // 192-bit key - call fn f once to gen 256 bits
            k1 = compute(k4, k3)
        } else {
            tmp = 0
            for i = 24; i < 32; i++ {
                tmp = (tmp << 8)
                tmp |= uint64(k[i])
            }

            // 256-bit key - pack k1 from key data
            k1.l = tmp >> 32
            k1.r = tmp
        }
    }

    // iterate over all LOKI97 rounds to generate the required subkeys
    for i = 0; i < NUM_SUBKEYS; i++ {
        t1 = add64(k1, k3)
        t2 = add64(t1, deltan)

        f_out = compute(t2, k2)

        SK[i].l = k4.l ^ f_out.l // compute next subkey value using fn f
        SK[i].r = k4.r ^ f_out.r

        k4 = k3                  // exchange the other words around
        k3 = k2
        k2 = k1
        k1 = SK[i]

        deltan = add64(deltan, DELTA) // next multiple of delta
    }

    return SK;
}
