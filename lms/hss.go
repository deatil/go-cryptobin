package lms

import (
    "io"
    "encoding/binary"
)

const HSS_MAX_LEVELS = 5

type HSSPublicKey struct {
    Levels int
    LmsPub PublicKey
}

func (pub *HSSPublicKey) Verify(msg []byte, sig []byte) bool {

    return false
}

type HSSPrivateKey struct {
    PublicKey HSSPublicKey
    LmsKey    [5]PrivateKey
    LmsSig    [4]Signature
}

func (priv *HSSPrivateKey) Public() HSSPublicKey {
    return priv.PublicKey
}

func (priv *HSSPrivateKey) Sign(rng io.Reader, msg []byte) ([]byte, error) {

    return nil, nil
}

type HSSOpts struct {
    Tc    ILmsParam
    Otstc ILmotsParam
}

func GenerateHSSKey(rng io.Reader, opts []HSSOpts) (HSSPrivateKey, error) {

    return HSSPrivateKey{}, nil
}

func HSSDigest(pub *PublicKey, q uint32, C [32]byte, data []byte) (dgst []byte) {
    var qbytes [4]byte
    binary.BigEndian.PutUint32(qbytes[:], q)

    otsParams := pub.otsType.Params()

    hasher := otsParams.Hash()
    hasher.Write(pub.id[:])
    hasher.Write(qbytes[:])
    hasher.Write(D_MESG[:])
    hasher.Write(C[:])
    hasher.Write(data)
    dgst = hasher.Sum(nil)

    return
}
