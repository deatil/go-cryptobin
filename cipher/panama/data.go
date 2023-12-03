package panama

type panamaData struct {
    state []uint32
    gamma []uint32
    pi    []uint32
    theta []uint32
}

func NewRegs(n uint32) *panamaData {
    data := &panamaData{}

    data.state = make([]uint32, n)
    data.gamma = make([]uint32, n)
    data.pi = make([]uint32, n)
    data.theta = make([]uint32, n)

    return data
}

/* move state between memory and local registers */
func (this *panamaData) READ_STATE_i(i uint32, state IState) {
    this.state[i] = state.Get(i)
}

func (this *panamaData) WRITE_STATE_i(i uint32, state IState) {
    state.With(i, this.state[i])
}

func (this *panamaData) READ_STATE(state IState) {
    this.READ_STATE_i(0, state)
    this.READ_STATE_i(1, state)
    this.READ_STATE_i(2, state)
    this.READ_STATE_i(3, state)
    this.READ_STATE_i(4, state)
    this.READ_STATE_i(5, state)
    this.READ_STATE_i(6, state)
    this.READ_STATE_i(7, state)
    this.READ_STATE_i(8, state)
    this.READ_STATE_i(9, state)
    this.READ_STATE_i(10, state)
    this.READ_STATE_i(11, state)
    this.READ_STATE_i(12, state)
    this.READ_STATE_i(13, state)
    this.READ_STATE_i(14, state)
    this.READ_STATE_i(15, state)
    this.READ_STATE_i(16, state)
}

func (this *panamaData) WRITE_STATE(state IState) {
    this.WRITE_STATE_i(0, state)
    this.WRITE_STATE_i(1, state)
    this.WRITE_STATE_i(2, state)
    this.WRITE_STATE_i(3, state)
    this.WRITE_STATE_i(4, state)
    this.WRITE_STATE_i(5, state)
    this.WRITE_STATE_i(6, state)
    this.WRITE_STATE_i(7, state)
    this.WRITE_STATE_i(8, state)
    this.WRITE_STATE_i(9, state)
    this.WRITE_STATE_i(10, state)
    this.WRITE_STATE_i(11, state)
    this.WRITE_STATE_i(12, state)
    this.WRITE_STATE_i(13, state)
    this.WRITE_STATE_i(14, state)
    this.WRITE_STATE_i(15, state)
    this.WRITE_STATE_i(16, state)
}

/* gamma, shift-invariant transformation a[i] XOR (a[i+1] OR NOT a[i+2]) */
func (this *panamaData) GAMMA_i(i, i_plus_1, i_plus_2 uint32) {
    this.gamma[i] = this.state[i] ^ (this.state[i_plus_1] | ^this.state[i_plus_2])
}

func (this *panamaData) GAMMA() {
    this.GAMMA_i( 0,  1,  2)
    this.GAMMA_i( 1,  2,  3)
    this.GAMMA_i( 2,  3,  4)
    this.GAMMA_i( 3,  4,  5)
    this.GAMMA_i( 4,  5,  6)
    this.GAMMA_i( 5,  6,  7)
    this.GAMMA_i( 6,  7,  8)
    this.GAMMA_i( 7,  8,  9)
    this.GAMMA_i( 8,  9, 10)
    this.GAMMA_i( 9, 10, 11)
    this.GAMMA_i(10, 11, 12)
    this.GAMMA_i(11, 12, 13)
    this.GAMMA_i(12, 13, 14)
    this.GAMMA_i(13, 14, 15)
    this.GAMMA_i(14, 15, 16)
    this.GAMMA_i(15, 16,  0)
    this.GAMMA_i(16,  0,  1)
}

/* pi, permute and cyclicly rotate the state words */
func (this *panamaData) PI_i(i, j, k uint32) {
    this.pi[i] = tau(this.gamma[j], k)
}

func (this *panamaData) PI() {
    this.pi[0] = this.gamma[0]
    this.PI_i( 1,  7,  1)
    this.PI_i( 2, 14,  3)
    this.PI_i( 3,  4,  6)
    this.PI_i( 4, 11, 10)
    this.PI_i( 5,  1, 15)
    this.PI_i( 6,  8, 21)
    this.PI_i( 7, 15, 28)
    this.PI_i( 8,  5,  4)
    this.PI_i( 9, 12, 13)
    this.PI_i(10,  2, 23)
    this.PI_i(11,  9,  2)
    this.PI_i(12, 16, 14)
    this.PI_i(13,  6, 27)
    this.PI_i(14, 13,  9)
    this.PI_i(15,  3, 24)
    this.PI_i(16, 10,  8)
}

/* theta, shift-invariant transformation a[i] XOR a[i+1] XOR a[i+4] */
func (this *panamaData) THETA_i(i, i_plus_1, i_plus_4 uint32) {
    this.theta[i] = this.pi[i] ^ this.pi[i_plus_1] ^ this.pi[i_plus_4]
}

func (this *panamaData) THETA() {
    this.THETA_i( 0,  1,  4)
    this.THETA_i( 1,  2,  5)
    this.THETA_i( 2,  3,  6)
    this.THETA_i( 3,  4,  7)
    this.THETA_i( 4,  5,  8)
    this.THETA_i( 5,  6,  9)
    this.THETA_i( 6,  7, 10)
    this.THETA_i( 7,  8, 11)
    this.THETA_i( 8,  9, 12)
    this.THETA_i( 9, 10, 13)
    this.THETA_i(10, 11, 14)
    this.THETA_i(11, 12, 15)
    this.THETA_i(12, 13, 16)
    this.THETA_i(13, 14,  0)
    this.THETA_i(14, 15,  1)
    this.THETA_i(15, 16,  2)
    this.THETA_i(16,  0,  3)
}

/* sigma, merge two buffer stages with current state */
func (this *panamaData) SIGMA_L_i(i uint32, L IState) {
    this.state[i] = this.theta[i] ^ L.Get(i-1)
}

func (this *panamaData) SIGMA_B_i(i uint32, b IState) {
    this.state[i] = this.theta[i] ^ b.Get(i-9)
}

func (this *panamaData) SIGMA(L IState, b IState) {
    this.state[0] = this.theta[0] ^ 0x00000001

    this.SIGMA_L_i(1, L)
    this.SIGMA_L_i(2, L)
    this.SIGMA_L_i(3, L)
    this.SIGMA_L_i(4, L)
    this.SIGMA_L_i(5, L)
    this.SIGMA_L_i(6, L)
    this.SIGMA_L_i(7, L)
    this.SIGMA_L_i(8, L)

    this.SIGMA_B_i(9, b)
    this.SIGMA_B_i(10, b)
    this.SIGMA_B_i(11, b)
    this.SIGMA_B_i(12, b)
    this.SIGMA_B_i(13, b)
    this.SIGMA_B_i(14, b)
    this.SIGMA_B_i(15, b)
    this.SIGMA_B_i(16, b)
}

/* lambda, update the 256-bit wide by 32-stage LFSR buffer */
func (this *panamaData) LAMBDA_25_i(i uint32, ptap_25 IState, ptap_0 IState) {
    tmp := ptap_25.Get(i) ^ ptap_0.Get((i+2) & (PAN_STAGE_SIZE-1))

    ptap_25.With(i, tmp)
}

func (this *panamaData) LAMBDA_0_i(i, source uint32, ptap_0 IState) {
    tmp := source ^ ptap_0.Get(i)

    ptap_0.With(i, tmp)
}

func (this *panamaData) LAMBDA_25_UPDATE(i uint32, ptap_25 IState, ptap_0 IState) {
    this.LAMBDA_25_i(0, ptap_25, ptap_0)
    this.LAMBDA_25_i(1, ptap_25, ptap_0)
    this.LAMBDA_25_i(2, ptap_25, ptap_0)
    this.LAMBDA_25_i(3, ptap_25, ptap_0)
    this.LAMBDA_25_i(4, ptap_25, ptap_0)
    this.LAMBDA_25_i(5, ptap_25, ptap_0)
    this.LAMBDA_25_i(6, ptap_25, ptap_0)
    this.LAMBDA_25_i(7, ptap_25, ptap_0)
}

func (this *panamaData) LAMBDA_0_PULL(ptap_0 IState) {
    this.LAMBDA_0_i(0, this.state[1], ptap_0)
    this.LAMBDA_0_i(1, this.state[2], ptap_0)
    this.LAMBDA_0_i(2, this.state[3], ptap_0)
    this.LAMBDA_0_i(3, this.state[4], ptap_0)
    this.LAMBDA_0_i(4, this.state[5], ptap_0)
    this.LAMBDA_0_i(5, this.state[6], ptap_0)
    this.LAMBDA_0_i(6, this.state[7], ptap_0)
    this.LAMBDA_0_i(7, this.state[8], ptap_0)
}

func (this *panamaData) LAMBDA_0_PUSH(ptap_0 IState, L IState) {
    this.LAMBDA_0_i(0, L.Get(0), ptap_0)
    this.LAMBDA_0_i(1, L.Get(1), ptap_0)
    this.LAMBDA_0_i(2, L.Get(2), ptap_0)
    this.LAMBDA_0_i(3, L.Get(3), ptap_0)
    this.LAMBDA_0_i(4, L.Get(4), ptap_0)
    this.LAMBDA_0_i(5, L.Get(5), ptap_0)
    this.LAMBDA_0_i(6, L.Get(6), ptap_0)
    this.LAMBDA_0_i(7, L.Get(7), ptap_0)
}

/* avoid temporary register for tap 31 by finishing updating tap 25 before updating tap 0 */
func (this *panamaData) LAMBDA_PULL(i uint32, ptap_25 IState, ptap_0 IState) {
    this.LAMBDA_25_UPDATE(i, ptap_25, ptap_0)
    this.LAMBDA_0_PULL(ptap_0)
}

func (this *panamaData) LAMBDA_PUSH(i uint32, ptap_25 IState, ptap_0 IState, L IState) {
    this.LAMBDA_25_UPDATE(i, ptap_25, ptap_0)
    this.LAMBDA_0_PUSH(ptap_0, L)

}

/**************************************************************************+
*
*  pan_pull() - Performs multiple iterations of the Panama 'Pull' operation.
*               The input and output arrays are treated as integer multiples
*               of Panama's natural 256-bit block size.
*
*               Input and output arrays may be disjoint or coincident but
*               may not be overlapped if offset from one another.
*
*               If 'In' is a NULL pointer then output is taken direct from
*               the state machine (used for hash output). If 'Out' is a NULL
*               pointer then a dummy 'Pull' is performed. Otherwise 'In' is
*               XOR combined with the state machine to produce 'Out'
*               (used for stream encryption / decryption).
*
+**************************************************************************/
func (this *panamaCipher) pan_pull(
    In []uint32,
    Out []uint32,
    pan_blocks uint32,
    buffer *PAN_BUFFER,
    state *PAN_STATE,
) []uint32 {
    /* 17-word finite-state machine  */
    var i uint32

    data := NewRegs(17)

    var tap_0 uint32

    var ptap_0, ptap_25 *PAN_STAGE
    var L, b *PAN_STAGE

    var null_in = [PAN_STAGE_SIZE]uint32{ 0, 0, 0, 0, 0, 0, 0, 0 }

    var dummy_out [PAN_STAGE_SIZE]uint32
    var in_step, out_step uint32

    in_step = PAN_STAGE_SIZE
    out_step = PAN_STAGE_SIZE

    if (len(In) == 0 || len(Out) == 0) {
        In = null_in[:]
        in_step = 0
    }

    if (len(Out) == 0) {
        Out = dummy_out[:]
        out_step = 0
    }

    /* copy buffer pointers and state to registers */
    tap_0 = uint32(buffer.tap_0)
    data.READ_STATE(state)

    newOut := make([]uint32, len(Out))

    /* rho, cascade of state update operations */

    for i = 0; i < pan_blocks; i++ {
        /* apply state output to crypto buffer */
        Out[0] = In[0] ^ data.state[9]
        Out[1] = In[1] ^ data.state[10]
        Out[2] = In[2] ^ data.state[11]
        Out[3] = In[3] ^ data.state[12]
        Out[4] = In[4] ^ data.state[13]
        Out[5] = In[5] ^ data.state[14]
        Out[6] = In[6] ^ data.state[15]
        Out[7] = In[7] ^ data.state[16]

        copy(newOut[i*out_step:], Out[:8])

        Out = Out[i*out_step:]
        In = In[i*in_step:]

        data.GAMMA()		/* perform non-linearity stage */

        data.PI()		/* perform bit-dispersion stage */

        data.THETA()		/* perform diffusion stage */

        /* calculate pointers to taps 4 and 16 for sigma based on current position of tap 0 */
        L = &buffer.stage[(tap_0 + 4) & (PAN_STAGES - 1)]
        b = &buffer.stage[(tap_0 + 16) & (PAN_STAGES - 1)]

        /* move tap_0 left by one stage, equivalent to shifting LFSR one stage right */
        tap_0 = (tap_0 - 1) & (PAN_STAGES - 1)

        /* set tap pointers for use by lambda */
        ptap_0 = &buffer.stage[tap_0]
        ptap_25 = &buffer.stage[(tap_0 + 25) & (PAN_STAGES - 1)]

        data.LAMBDA_PULL(i, ptap_25, ptap_0);	/* update the LFSR buffer */

        /* postpone sigma until after lambda in order to avoid extra temporaries for feedback path */
        /* note that sigma gets to use the old positions of taps 4 and 16 */

        data.SIGMA(L, b)		/* perform buffer injection stage */
    }

    /* write buffer pointer and state back to memory */
    buffer.tap_0 = int32(tap_0)
    data.WRITE_STATE(state)

    return newOut
}

/**************************************************************************+
*
*  pan_push() - Performs multiple iterations of the Panama 'Push' operation.
*               The input array is treated as an integer multiple of the
*               256-bit blocks which are Panama's natural input size.
*
+**************************************************************************/
func (this *panamaCipher) pan_push(
    In []uint32,
    pan_blocks uint32,
    buffer *PAN_BUFFER,
    state *PAN_STATE,
) {
    /* 17-word finite-state machine  */
    var i uint32

    data := NewRegs(17)

    var tap_0 uint32
    var ptap_0, ptap_25 *PAN_STAGE
    var L, b *PAN_STAGE

    /* copy buffer pointers and state to registers */
    tap_0 = uint32(buffer.tap_0)
    data.READ_STATE(state)

    var pan_states [8]uint32

    copy(pan_states[0:], In[:PAN_STAGE_SIZE])

    L = &PAN_STAGE{pan_states}	/* we assume pointer to input buffer is compatible with pointer to PAN_STAGE */

    for i = 0; i < PAN_STAGE_SIZE; i++ {
        L.With(i, byteswap32(L.Get(i)))
    }

    /* rho, cascade of state update operations */

    for i = 0; i < pan_blocks; i++ {
        data.GAMMA()		/* perform non-linearity stage */

        data.PI()		/* perform bit-dispersion stage */

        data.THETA()		/* perform diffusion stage */

        /* calculate pointer to tap 16 for sigma based on current position of tap 0 */
        b = &buffer.stage[(tap_0 + 16) & (PAN_STAGES - 1)]

        /* move tap_0 left by one stage, equivalent to shifting LFSR one stage right */
        tap_0 = (tap_0 - 1) & (PAN_STAGES - 1)

        /* set tap pointers for use by lambda */
        ptap_0 = &buffer.stage[tap_0]
        ptap_25 = &buffer.stage[(tap_0 + 25) & (PAN_STAGES - 1)]

        data.LAMBDA_PUSH(i, ptap_25, ptap_0, L)	/* update the LFSR buffer */

        /* postpone sigma until after lambda in order to avoid extra temporaries for feedback path */
        /* note that sigma gets to use the old positions of taps 4 and 16 */

        data.SIGMA(L, b)		/* perform buffer injection stage */

        /* In += PAN_STAGE_SIZE; */
        copy(pan_states[0:], In[(i+1)*PAN_STAGE_SIZE:(i+2)*PAN_STAGE_SIZE])
        L = &PAN_STAGE{pan_states}
    }

    /* write buffer pointer and state back to memory */
    buffer.tap_0 = int32(tap_0)
    data.WRITE_STATE(state)
}

/**************************************************************************+
*
*  pan_reset() - Initializes an LFSR buffer and Panama state machine to
*                all zeros, ready for a new hash to be accumulated or to
*                re-synchronize or start up an encryption key-stream.
*
+**************************************************************************/
func (this *panamaCipher) pan_reset(buffer *PAN_BUFFER, state *PAN_STATE) {
    var i, j int32

    buffer.tap_0 = 0

    for j = 0; j < PAN_STAGES; j++ {
        for i = 0; i < PAN_STAGE_SIZE; i++ {
            buffer.stage[j].word[i] = 0
        }
    }

    for i = 0; i < PAN_STATE_SIZE; i++ {
        state.word[i] = 0
    }
}
