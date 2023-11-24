package loki97

const NUM_SUBKEYS = 48
var DELTA = ULONG64{0x9E3779B9, 0x7F4A7C15}

func makeKey(k []byte) [NUM_SUBKEYS]ULONG64 {
    var SK [NUM_SUBKEYS]ULONG64 // array of subkeys

    var deltan ULONG64 = DELTA  // multiples of delta

    var i int16 = 0             // index into key input
    var k4, k3, k2, k1 ULONG64  // key schedule 128-bit entities
    var f_out ULONG64           // fn f output value for debug
    var t1, t2 ULONG64

    // pack key into 128-bit entities: k4, k3, k2, k1
    k4 = byteToULONG64(k[0:8])
    k3 = byteToULONG64(k[8:16])

    if len(k) == 16 {
        // 128-bit key - call fn f twice to gen 256 bits
        k2 = compute(k3, k4)
        k1 = compute(k4, k3)
    } else {
        // 192 or 256-bit key - pack k2 from key data
        k2 = byteToULONG64(k[16:24])

        if len(k) == 24 {
            // 192-bit key - call fn f once to gen 256 bits
            k1 = compute(k4, k3)
        } else {
            // 256-bit key - pack k1 from key data
            k1 = byteToULONG64(k[24:32])
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
