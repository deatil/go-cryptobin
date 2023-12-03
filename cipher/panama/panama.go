package panama

import (
    "strconv"
    "crypto/cipher"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "crypto/panama: invalid key size " + strconv.Itoa(int(k))
}

const NULL = 0

const WORDLENGTH = 32
const ONES       = 0xffffffff

const PAN_STAGE_SIZE = 8
const PAN_STAGES     = 32
const PAN_STATE_SIZE = 17

type panamaCipher struct {
    buffer PAN_BUFFER
    stated PAN_STATE
    wkeymat [8]uint32
    keymat  [32]byte
    keymat_pointer int32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(panamaCipher)

    c.buffer = PAN_BUFFER{}
    c.stated = PAN_STATE{}

    keys := make([]int8, 32)
    for i, kk := range key {
        keys[i] = int8(kk)
    }

    c.set_key(keys, WORDLENGTH, nil, 0)

    return c, nil
}

func (this *panamaCipher) set_key(
    in_key []int8,
    keysize int32,
    init_vec []int8,
    vecsize int32,
) {
    var keyblocks int32 = (8 * keysize) / (PAN_STAGE_SIZE * WORDLENGTH);
    var vecblocks int32 = (8 * vecsize) / (PAN_STAGE_SIZE * WORDLENGTH);

    var i int32
    for i = 0; i < 8; i++ {
        this.keymat[i] = byte(this.wkeymat[i])
    }

    in_keys := make([]uint32, len(in_key))
    for i, k := range in_key {
        in_keys[i] = uint32(k)
    }

    /* initialize the Panama state machine for a fresh crypting operation */
    this.pan_reset(&this.buffer, &this.stated)
    this.pan_push(in_keys, uint32(keyblocks), &this.buffer, &this.stated)

    if len(init_vec) != 0 {
        init_vecs := make([]uint32, len(init_vec))
        for i, v := range init_vec {
            init_vecs[i] = uint32(v)
        }

        this.pan_push(init_vecs, uint32(vecblocks), &this.buffer, &this.stated)
    }

    this.pan_pull(nil, nil, 32, &this.buffer, &this.stated);

    wkeymat := this.pan_pull(nil, this.wkeymat[:], 1, &this.buffer, &this.stated)
    copy(this.wkeymat[0:], wkeymat)

    this.keymat_pointer = 0

    for i = 0; i < 8; i++ {
        this.wkeymat[i] = byteswap32(this.wkeymat[i])
    }
}

func (this *panamaCipher) XORKeyStream(dst, src []byte) {
    var i int32
    var j int32

    /* initialize the Panama state machine for a fresh crypting operation */
    for i = 0; i < int32(len(src)); i++ {
        if this.keymat_pointer == 32 {
            wkeymat := this.pan_pull(nil, this.wkeymat[:], 1, &this.buffer, &this.stated)
            copy(this.wkeymat[0:], wkeymat)

            this.keymat_pointer = 0

            for j = 0; j < 8; j++ {
                this.wkeymat[j] = byteswap32(this.wkeymat[j])
            }
        }

        dst[i] ^= this.keymat[this.keymat_pointer];
        this.keymat_pointer++
    }
}

